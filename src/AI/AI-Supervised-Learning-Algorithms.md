# Algoritmos de Aprendizado Supervisionado

{{#include ../banners/hacktricks-training.md}}

## Informações Básicas

O aprendizado supervisionado utiliza dados rotulados para treinar modelos que podem fazer previsões sobre novas entradas não vistas. Na cibersegurança, o aprendizado de máquina supervisionado é amplamente aplicado a tarefas como detecção de intrusões (classificando o tráfego de rede como *normal* ou *ataque*), detecção de malware (distinguindo software malicioso de benigno), detecção de phishing (identificando sites ou e-mails fraudulentos) e filtragem de spam, entre outros. Cada algoritmo tem suas forças e é adequado para diferentes tipos de problemas (classificação ou regressão). Abaixo, revisamos os principais algoritmos de aprendizado supervisionado, explicamos como funcionam e demonstramos seu uso em conjuntos de dados reais de cibersegurança. Também discutimos como a combinação de modelos (aprendizado em conjunto) pode frequentemente melhorar o desempenho preditivo.

## Algoritmos

-   **Regressão Linear:** Um algoritmo de regressão fundamental para prever resultados numéricos ajustando uma equação linear aos dados.

-   **Regressão Logística:** Um algoritmo de classificação (apesar do nome) que usa uma função logística para modelar a probabilidade de um resultado binário.

-   **Árvores de Decisão:** Modelos estruturados em árvore que dividem os dados por características para fazer previsões; frequentemente usados por sua interpretabilidade.

-   **Florestas Aleatórias:** Um conjunto de árvores de decisão (via bagging) que melhora a precisão e reduz o overfitting.

-   **Máquinas de Vetores de Suporte (SVM):** Classificadores de margem máxima que encontram o hiperplano separador ótimo; podem usar kernels para dados não lineares.

-   **Naive Bayes:** Um classificador probabilístico baseado no teorema de Bayes com uma suposição de independência das características, famoso por seu uso em filtragem de spam.

-   **k-Vizinhos Mais Próximos (k-NN):** Um classificador simples "baseado em instâncias" que rotula uma amostra com base na classe majoritária de seus vizinhos mais próximos.

-   **Máquinas de Aumento de Gradiente:** Modelos em conjunto (por exemplo, XGBoost, LightGBM) que constroem um preditor forte adicionando sequencialmente aprendizes mais fracos (tipicamente árvores de decisão).

Cada seção abaixo fornece uma descrição aprimorada do algoritmo e um **exemplo de código Python** usando bibliotecas como `pandas` e `scikit-learn` (e `PyTorch` para o exemplo de rede neural). Os exemplos usam conjuntos de dados de cibersegurança disponíveis publicamente (como NSL-KDD para detecção de intrusões e um conjunto de dados de Sites de Phishing) e seguem uma estrutura consistente:

1.  **Carregar o conjunto de dados** (baixar via URL se disponível).

2.  **Pré-processar os dados** (por exemplo, codificar características categóricas, escalar valores, dividir em conjuntos de treino/teste).

3.  **Treinar o modelo** nos dados de treinamento.

4.  **Avaliar** em um conjunto de teste usando métricas: precisão, precisão, recall, F1-score e ROC AUC para classificação (e erro quadrático médio para regressão).

Vamos mergulhar em cada algoritmo:

### Regressão Linear

A regressão linear é um algoritmo de **regressão** usado para prever valores numéricos contínuos. Assume uma relação linear entre as características de entrada (variáveis independentes) e a saída (variável dependente). O modelo tenta ajustar uma linha reta (ou hiperplano em dimensões superiores) que melhor descreve a relação entre as características e o alvo. Isso é tipicamente feito minimizando a soma dos erros quadráticos entre os valores previstos e reais (método dos Mínimos Quadrados Ordinários).

A forma mais simples de representar a regressão linear é com uma linha:
```plaintext
y = mx + b
```
Onde:

- `y` é o valor previsto (saída)
- `m` é a inclinação da linha (coeficiente)
- `x` é a característica de entrada
- `b` é o intercepto y

O objetivo da regressão linear é encontrar a linha que melhor se ajusta e que minimiza a diferença entre os valores previstos e os valores reais no conjunto de dados. Claro, isso é muito simples, seria uma linha reta separando 2 categorias, mas se mais dimensões forem adicionadas, a linha se torna mais complexa:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Casos de uso em cibersegurança:* A regressão linear em si é menos comum para tarefas de segurança principais (que geralmente são de classificação), mas pode ser aplicada para prever resultados numéricos. Por exemplo, pode-se usar a regressão linear para **prever o volume de tráfego de rede** ou **estimar o número de ataques em um período de tempo** com base em dados históricos. Também poderia prever uma pontuação de risco ou o tempo esperado até a detecção de um ataque, dado certos métricas do sistema. Na prática, algoritmos de classificação (como regressão logística ou árvores) são mais frequentemente usados para detectar intrusões ou malware, mas a regressão linear serve como uma base e é útil para análises orientadas a regressão.

#### **Características principais da Regressão Linear:**

-   **Tipo de Problema:** Regressão (previsão de valores contínuos). Não é adequada para classificação direta, a menos que um limite seja aplicado à saída.

-   **Interpretabilidade:** Alta -- os coeficientes são fáceis de interpretar, mostrando o efeito linear de cada recurso.

-   **Vantagens:** Simples e rápido; uma boa linha de base para tarefas de regressão; funciona bem quando a verdadeira relação é aproximadamente linear.

-   **Limitações:** Não consegue capturar relações complexas ou não lineares (sem engenharia de recursos manual); propenso a subajuste se as relações forem não lineares; sensível a outliers que podem distorcer os resultados.

-   **Encontrando o Melhor Ajuste:** Para encontrar a linha de melhor ajuste que separa as possíveis categorias, usamos um método chamado **Ordinary Least Squares (OLS)**. Este método minimiza a soma das diferenças quadradas entre os valores observados e os valores previstos pelo modelo linear.

<details>
<summary>Exemplo -- Prevendo Duração da Conexão (Regressão) em um Conjunto de Dados de Intrusão
</summary>
Abaixo demonstramos a regressão linear usando o conjunto de dados de cibersegurança NSL-KDD. Trataremos isso como um problema de regressão prevendo a `duração` das conexões de rede com base em outros recursos. (Na realidade, `duração` é um recurso do NSL-KDD; usamos aqui apenas para ilustrar a regressão.) Carregamos o conjunto de dados, o pré-processamos (codificamos recursos categóricos), treinamos um modelo de regressão linear e avaliamos o Erro Quadrático Médio (MSE) e a pontuação R² em um conjunto de teste.
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
Neste exemplo, o modelo de regressão linear tenta prever a `duração` da conexão a partir de outras características da rede. Medimos o desempenho com o Erro Quadrático Médio (MSE) e R². Um R² próximo de 1.0 indicaria que o modelo explica a maior parte da variância em `duração`, enquanto um R² baixo ou negativo indica um ajuste ruim. (Não se surpreenda se o R² for baixo aqui -- prever `duração` pode ser difícil a partir das características dadas, e a regressão linear pode não capturar os padrões se forem complexos.)
</details>

### Regressão Logística

A regressão logística é um algoritmo de **classificação** que modela a probabilidade de que uma instância pertença a uma classe particular (tipicamente a classe "positiva"). Apesar do nome, a *regressão* logística é usada para resultados discretos (diferente da regressão linear, que é para resultados contínuos). É especialmente utilizada para **classificação binária** (duas classes, por exemplo, malicioso vs. benigno), mas pode ser estendida para problemas de múltiplas classes (usando abordagens softmax ou um-contra-todos).

A regressão logística utiliza a função logística (também conhecida como função sigmoide) para mapear valores previstos em probabilidades. Note que a função sigmoide é uma função com valores entre 0 e 1 que cresce em uma curva em forma de S de acordo com as necessidades da classificação, o que é útil para tarefas de classificação binária. Portanto, cada característica de cada entrada é multiplicada pelo seu peso atribuído, e o resultado é passado pela função sigmoide para produzir uma probabilidade:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Onde:

- `p(y=1|x)` é a probabilidade de que a saída `y` seja 1 dado a entrada `x`
- `e` é a base do logaritmo natural
- `z` é uma combinação linear das características de entrada, tipicamente representada como `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Note como, novamente, em sua forma mais simples, é uma linha reta, mas em casos mais complexos torna-se um hiperpano com várias dimensões (uma por característica).

> [!TIP]
> *Casos de uso em cibersegurança:* Como muitos problemas de segurança são essencialmente decisões de sim/não, a regressão logística é amplamente utilizada. Por exemplo, um sistema de detecção de intrusões pode usar regressão logística para decidir se uma conexão de rede é um ataque com base nas características dessa conexão. Na detecção de phishing, a regressão logística pode combinar características de um site (comprimento da URL, presença do símbolo "@", etc.) em uma probabilidade de ser phishing. Foi utilizada em filtros de spam de primeira geração e continua sendo uma base forte para muitas tarefas de classificação.

#### Regressão Logística para classificação não binária

A regressão logística é projetada para classificação binária, mas pode ser estendida para lidar com problemas de múltiplas classes usando técnicas como **one-vs-rest** (OvR) ou **regressão softmax**. No OvR, um modelo de regressão logística separado é treinado para cada classe, tratando-a como a classe positiva contra todas as outras. A classe com a maior probabilidade prevista é escolhida como a previsão final. A regressão softmax generaliza a regressão logística para múltiplas classes aplicando a função softmax à camada de saída, produzindo uma distribuição de probabilidade sobre todas as classes.

#### **Características principais da Regressão Logística:**

-   **Tipo de Problema:** Classificação (geralmente binária). Prediz a probabilidade da classe positiva.

-   **Interpretabilidade:** Alta -- como na regressão linear, os coeficientes das características podem indicar como cada característica influencia os log-odds do resultado. Essa transparência é frequentemente apreciada na segurança para entender quais fatores contribuem para um alerta.

-   **Vantagens:** Simples e rápido de treinar; funciona bem quando a relação entre características e log-odds do resultado é linear. Produz probabilidades, permitindo a pontuação de risco. Com regularização apropriada, generaliza bem e pode lidar com multicolinearidade melhor do que a regressão linear simples.

-   **Limitações:** Assume uma fronteira de decisão linear no espaço das características (falha se a verdadeira fronteira for complexa/não linear). Pode ter desempenho inferior em problemas onde interações ou efeitos não lineares são críticos, a menos que você adicione manualmente características polinomiais ou de interação. Além disso, a regressão logística é menos eficaz se as classes não forem facilmente separáveis por uma combinação linear de características.

<details>
<summary>Exemplo -- Detecção de Sites de Phishing com Regressão Logística:</summary>

Usaremos um **Conjunto de Dados de Sites de Phishing** (do repositório UCI) que contém características extraídas de sites (como se a URL tem um endereço IP, a idade do domínio, presença de elementos suspeitos em HTML, etc.) e um rótulo indicando se o site é phishing ou legítimo. Treinamos um modelo de regressão logística para classificar sites e, em seguida, avaliamos sua precisão, precisão, recall, F1-score e ROC AUC em uma divisão de teste.
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
Neste exemplo de detecção de phishing, a regressão logística produz uma probabilidade para cada site ser phishing. Ao avaliar a acurácia, precisão, recall e F1, obtemos uma noção do desempenho do modelo. Por exemplo, um alto recall significaria que ele captura a maioria dos sites de phishing (importante para a segurança para minimizar ataques perdidos), enquanto alta precisão significa que tem poucos alarmes falsos (importante para evitar fadiga do analista). O ROC AUC (Área Sob a Curva ROC) fornece uma medida de desempenho independente de limiar (1.0 é ideal, 0.5 não é melhor do que o acaso). A regressão logística geralmente se sai bem em tais tarefas, mas se a fronteira de decisão entre sites de phishing e legítimos for complexa, modelos não lineares mais poderosos podem ser necessários.

</details>

### Árvores de Decisão

Uma árvore de decisão é um **algoritmo de aprendizado supervisionado** versátil que pode ser usado tanto para tarefas de classificação quanto de regressão. Ela aprende um modelo hierárquico em forma de árvore de decisões com base nas características dos dados. Cada nó interno da árvore representa um teste em uma característica particular, cada ramo representa um resultado desse teste, e cada nó folha representa uma classe prevista (para classificação) ou valor (para regressão).

Para construir uma árvore, algoritmos como CART (Classification and Regression Tree) usam medidas como **impureza de Gini** ou **ganho de informação (entropia)** para escolher a melhor característica e limiar para dividir os dados em cada etapa. O objetivo em cada divisão é particionar os dados para aumentar a homogeneidade da variável alvo nos subconjuntos resultantes (para classificação, cada nó visa ser o mais puro possível, contendo predominantemente uma única classe).

As árvores de decisão são **altamente interpretáveis** -- pode-se seguir o caminho da raiz à folha para entender a lógica por trás de uma previsão (por exemplo, *"SE `service = telnet` E `src_bytes > 1000` E `failed_logins > 3` ENTÃO classificar como ataque"*). Isso é valioso em cibersegurança para explicar por que um determinado alerta foi gerado. As árvores podem lidar naturalmente com dados numéricos e categóricos e requerem pouca pré-processamento (por exemplo, escalonamento de características não é necessário).

No entanto, uma única árvore de decisão pode facilmente se ajustar demais aos dados de treinamento, especialmente se crescer profundamente (muitas divisões). Técnicas como poda (limitar a profundidade da árvore ou exigir um número mínimo de amostras por folha) são frequentemente usadas para prevenir o sobreajuste.

Existem 3 componentes principais de uma árvore de decisão:
- **Nó Raiz**: O nó superior da árvore, representando todo o conjunto de dados.
- **Nódulos Internos**: Nós que representam características e decisões com base nessas características.
- **Nódulos Folha**: Nós que representam o resultado final ou previsão.

Uma árvore pode acabar parecendo assim:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Casos de uso em cibersegurança:* Árvores de decisão têm sido usadas em sistemas de detecção de intrusões para derivar **regras** para identificar ataques. Por exemplo, IDSs antigos como sistemas baseados em ID3/C4.5 gerariam regras legíveis por humanos para distinguir tráfego normal de tráfego malicioso. Elas também são usadas na análise de malware para decidir se um arquivo é malicioso com base em seus atributos (tamanho do arquivo, entropia da seção, chamadas de API, etc.). A clareza das árvores de decisão as torna úteis quando a transparência é necessária -- um analista pode inspecionar a árvore para validar a lógica de detecção.

#### **Características principais das Árvores de Decisão:**

-   **Tipo de Problema:** Tanto classificação quanto regressão. Comumente usadas para classificação de ataques vs. tráfego normal, etc.

-   **Interpretabilidade:** Muito alta -- as decisões do modelo podem ser visualizadas e entendidas como um conjunto de regras se-então. Esta é uma grande vantagem em segurança para confiança e verificação do comportamento do modelo.

-   **Vantagens:** Podem capturar relações não lineares e interações entre características (cada divisão pode ser vista como uma interação). Não há necessidade de escalar características ou codificar variáveis categóricas em one-hot -- as árvores lidam com isso nativamente. Inferência rápida (a previsão é apenas seguir um caminho na árvore).

-   **Limitações:** Propensas ao overfitting se não controladas (uma árvore profunda pode memorizar o conjunto de treinamento). Elas podem ser instáveis -- pequenas mudanças nos dados podem levar a uma estrutura de árvore diferente. Como modelos únicos, sua precisão pode não corresponder a métodos mais avançados (conjuntos como Random Forests geralmente têm um desempenho melhor ao reduzir a variância).

-   **Encontrando a Melhor Divisão:**
- **Impureza de Gini**: Mede a impureza de um nó. Uma impureza de Gini mais baixa indica uma melhor divisão. A fórmula é:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Onde `p_i` é a proporção de instâncias na classe `i`.

- **Entropia**: Mede a incerteza no conjunto de dados. Uma entropia mais baixa indica uma melhor divisão. A fórmula é:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Onde `p_i` é a proporção de instâncias na classe `i`.

- **Ganho de Informação**: A redução na entropia ou impureza de Gini após uma divisão. Quanto maior o ganho de informação, melhor a divisão. É calculado como:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Além disso, uma árvore é finalizada quando:
- Todas as instâncias em um nó pertencem à mesma classe. Isso pode levar ao overfitting.
- A profundidade máxima (codificada) da árvore é alcançada. Esta é uma forma de prevenir overfitting.
- O número de instâncias em um nó está abaixo de um certo limite. Esta também é uma forma de prevenir overfitting.
- O ganho de informação de divisões adicionais está abaixo de um certo limite. Esta também é uma forma de prevenir overfitting.

<details>
<summary>Exemplo -- Árvore de Decisão para Detecção de Intrusões:</summary>
Vamos treinar uma árvore de decisão no conjunto de dados NSL-KDD para classificar conexões de rede como *normal* ou *ataque*. NSL-KDD é uma versão aprimorada do clássico conjunto de dados KDD Cup 1999, com características como tipo de protocolo, serviço, duração, número de logins falhados, etc., e um rótulo indicando o tipo de ataque ou "normal". Vamos mapear todos os tipos de ataque para uma classe "anômala" (classificação binária: normal vs anômala). Após o treinamento, avaliaremos o desempenho da árvore no conjunto de teste.
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
Neste exemplo de árvore de decisão, limitamos a profundidade da árvore a 10 para evitar overfitting extremo (o parâmetro `max_depth=10`). As métricas mostram quão bem a árvore distingue tráfego normal de tráfego de ataque. Um alto recall significaria que ela captura a maioria dos ataques (importante para um IDS), enquanto alta precisão significa poucos alarmes falsos. Árvores de decisão geralmente alcançam uma precisão decente em dados estruturados, mas uma única árvore pode não atingir o melhor desempenho possível. No entanto, a *interpretabilidade* do modelo é uma grande vantagem -- poderíamos examinar as divisões da árvore para ver, por exemplo, quais características (e.g., `service`, `src_bytes`, etc.) são mais influentes em sinalizar uma conexão como maliciosa.

</details>

### Florestas Aleatórias

Random Forest é um método de **aprendizado em conjunto** que se baseia em árvores de decisão para melhorar o desempenho. Uma random forest treina várias árvores de decisão (daí "floresta") e combina suas saídas para fazer uma previsão final (para classificação, tipicamente por votação majoritária). As duas principais ideias em uma random forest são **bagging** (bootstrap aggregating) e **aleatoriedade de características**:

-   **Bagging:** Cada árvore é treinada em uma amostra bootstrap aleatória dos dados de treinamento (amostrada com reposição). Isso introduz diversidade entre as árvores.

-   **Aleatoriedade de Características:** Em cada divisão de uma árvore, um subconjunto aleatório de características é considerado para a divisão (em vez de todas as características). Isso decorre ainda mais as árvores.

Ao fazer a média dos resultados de muitas árvores, a random forest reduz a variância que uma única árvore de decisão pode ter. Em termos simples, árvores individuais podem overfit ou ser ruidosas, mas um grande número de árvores diversas votando juntas suaviza esses erros. O resultado é frequentemente um modelo com **maior precisão** e melhor generalização do que uma única árvore de decisão. Além disso, florestas aleatórias podem fornecer uma estimativa da importância das características (observando quanto cada característica reduz a impureza em média).

Florestas aleatórias se tornaram um **cavalo de batalha na cibersegurança** para tarefas como detecção de intrusões, classificação de malware e detecção de spam. Elas geralmente apresentam bom desempenho imediatamente com mínima configuração e podem lidar com grandes conjuntos de características. Por exemplo, na detecção de intrusões, uma random forest pode superar uma árvore de decisão individual ao capturar padrões de ataques mais sutis com menos falsos positivos. Pesquisas mostraram que florestas aleatórias apresentam desempenho favorável em comparação com outros algoritmos na classificação de ataques em conjuntos de dados como NSL-KDD e UNSW-NB15.

#### **Características principais das Florestas Aleatórias:**

-   **Tipo de Problema:** Principalmente classificação (também usadas para regressão). Muito bem adequadas para dados estruturados de alta dimensão comuns em logs de segurança.

-   **Interpretabilidade:** Menor do que uma única árvore de decisão -- você não pode visualizar ou explicar facilmente centenas de árvores de uma vez. No entanto, as pontuações de importância das características fornecem alguma visão sobre quais atributos são mais influentes.

-   **Vantagens:** Geralmente maior precisão do que modelos de árvore única devido ao efeito de conjunto. Robusta ao overfitting -- mesmo que árvores individuais overfit, o conjunto generaliza melhor. Lida com características numéricas e categóricas e pode gerenciar dados ausentes até certo ponto. Também é relativamente robusta a outliers.

-   **Limitações:** O tamanho do modelo pode ser grande (muitas árvores, cada uma potencialmente profunda). As previsões são mais lentas do que uma única árvore (já que você deve agregar sobre muitas árvores). Menos interpretável -- embora você saiba quais características são importantes, a lógica exata não é facilmente rastreável como uma regra simples. Se o conjunto de dados for extremamente de alta dimensão e esparso, treinar uma floresta muito grande pode ser computacionalmente pesado.

-   **Processo de Treinamento:**
1. **Amostragem Bootstrap**: Amostrar aleatoriamente os dados de treinamento com reposição para criar múltiplos subconjuntos (amostras bootstrap).
2. **Construção da Árvore**: Para cada amostra bootstrap, construir uma árvore de decisão usando um subconjunto aleatório de características em cada divisão. Isso introduz diversidade entre as árvores.
3. **Agregação**: Para tarefas de classificação, a previsão final é feita por meio de uma votação majoritária entre as previsões de todas as árvores. Para tarefas de regressão, a previsão final é a média das previsões de todas as árvores.

<details>
<summary>Exemplo -- Random Forest para Detecção de Intrusões (NSL-KDD):</summary>
Usaremos o mesmo conjunto de dados NSL-KDD (rotulado binariamente como normal vs anomalia) e treinaremos um classificador Random Forest. Esperamos que a random forest tenha um desempenho tão bom quanto ou melhor do que a árvore de decisão única, graças à média do conjunto reduzindo a variância. Avaliaremos com as mesmas métricas.
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
A floresta aleatória geralmente alcança resultados fortes nesta tarefa de detecção de intrusões. Podemos observar uma melhoria em métricas como F1 ou AUC em comparação com a árvore de decisão única, especialmente em recall ou precisão, dependendo dos dados. Isso está alinhado com a compreensão de que *"Random Forest (RF) é um classificador em conjunto e se sai bem em comparação com outros classificadores tradicionais para a classificação eficaz de ataques."*. Em um contexto de operações de segurança, um modelo de floresta aleatória pode sinalizar ataques de forma mais confiável, reduzindo alarmes falsos, graças à média de muitas regras de decisão. A importância das características da floresta pode nos dizer quais características da rede são mais indicativas de ataques (por exemplo, certos serviços de rede ou contagens incomuns de pacotes).

</details>

### Máquinas de Vetores de Suporte (SVM)

As Máquinas de Vetores de Suporte são modelos de aprendizado supervisionado poderosos usados principalmente para classificação (e também regressão como SVR). Uma SVM tenta encontrar o **hiperplano separador ótimo** que maximiza a margem entre duas classes. Apenas um subconjunto de pontos de treinamento (os "vetores de suporte" mais próximos da fronteira) determina a posição deste hiperplano. Ao maximizar a margem (distância entre vetores de suporte e o hiperplano), as SVMs tendem a alcançar uma boa generalização.

A chave para o poder da SVM é a capacidade de usar **funções de kernel** para lidar com relações não lineares. Os dados podem ser implicitamente transformados em um espaço de características de dimensão superior onde um separador linear pode existir. Os kernels comuns incluem polinomial, função de base radial (RBF) e sigmoide. Por exemplo, se as classes de tráfego de rede não forem separáveis linearmente no espaço de características bruto, um kernel RBF pode mapeá-las em uma dimensão superior onde a SVM encontra uma divisão linear (que corresponde a uma fronteira não linear no espaço original). A flexibilidade de escolher kernels permite que as SVMs enfrentem uma variedade de problemas.

As SVMs são conhecidas por se saírem bem em situações com espaços de características de alta dimensão (como dados de texto ou sequências de opcodes de malware) e em casos onde o número de características é grande em relação ao número de amostras. Elas foram populares em muitas aplicações iniciais de cibersegurança, como classificação de malware e detecção de intrusões baseadas em anomalias nos anos 2000, frequentemente mostrando alta precisão.

No entanto, as SVMs não escalam facilmente para conjuntos de dados muito grandes (a complexidade de treinamento é super-linear em relação ao número de amostras, e o uso de memória pode ser alto, pois pode precisar armazenar muitos vetores de suporte). Na prática, para tarefas como detecção de intrusões em rede com milhões de registros, a SVM pode ser muito lenta sem um cuidadoso subsampling ou uso de métodos aproximados.

#### **Características principais da SVM:**

-   **Tipo de Problema:** Classificação (binária ou multiclass via um-contra-um/um-contra-todos) e variantes de regressão. Frequentemente usada em classificação binária com separação de margem clara.

-   **Interpretabilidade:** Média -- As SVMs não são tão interpretáveis quanto árvores de decisão ou regressão logística. Embora você possa identificar quais pontos de dados são vetores de suporte e ter uma noção de quais características podem ser influentes (através dos pesos no caso do kernel linear), na prática, as SVMs (especialmente com kernels não lineares) são tratadas como classificadores de caixa-preta.

-   **Vantagens:** Eficaz em espaços de alta dimensão; pode modelar fronteiras de decisão complexas com truque de kernel; robusta ao overfitting se a margem for maximizada (especialmente com um parâmetro de regularização C adequado); funciona bem mesmo quando as classes não estão separadas por uma grande distância (encontra a melhor fronteira de compromisso).

-   **Limitações:** **Intensivo em computação** para grandes conjuntos de dados (tanto o treinamento quanto a previsão escalam mal à medida que os dados crescem). Requer ajuste cuidadoso dos parâmetros de kernel e regularização (C, tipo de kernel, gama para RBF, etc.). Não fornece diretamente saídas probabilísticas (embora se possa usar o escalonamento de Platt para obter probabilidades). Além disso, as SVMs podem ser sensíveis à escolha dos parâmetros do kernel --- uma escolha ruim pode levar a underfit ou overfit.

*Casos de uso em cibersegurança:* As SVMs têm sido usadas em **detecção de malware** (por exemplo, classificando arquivos com base em características extraídas ou sequências de opcodes), **detecção de anomalias em rede** (classificando tráfego como normal vs malicioso) e **detecção de phishing** (usando características de URLs). Por exemplo, uma SVM poderia pegar características de um e-mail (contagens de certas palavras-chave, pontuações de reputação do remetente, etc.) e classificá-lo como phishing ou legítimo. Elas também foram aplicadas à **detecção de intrusões** em conjuntos de características como KDD, frequentemente alcançando alta precisão à custa de computação.

<details>
<summary>Exemplo -- SVM para Classificação de Malware:</summary>
Usaremos o conjunto de dados de sites de phishing novamente, desta vez com uma SVM. Como as SVMs podem ser lentas, usaremos um subconjunto dos dados para treinamento, se necessário (o conjunto de dados tem cerca de 11k instâncias, que a SVM pode lidar razoavelmente). Usaremos um kernel RBF, que é uma escolha comum para dados não lineares, e habilitaremos estimativas de probabilidade para calcular o ROC AUC.
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
O modelo SVM irá gerar métricas que podemos comparar com a regressão logística na mesma tarefa. Podemos descobrir que o SVM alcança uma alta precisão e AUC se os dados estiverem bem separados pelas características. Por outro lado, se o conjunto de dados tiver muito ruído ou classes sobrepostas, o SVM pode não superar significativamente a regressão logística. Na prática, os SVMs podem oferecer um impulso quando há relações complexas e não lineares entre características e classe -- o kernel RBF pode capturar limites de decisão curvados que a regressão logística perderia. Como em todos os modelos, um ajuste cuidadoso dos parâmetros `C` (regularização) e do kernel (como `gamma` para RBF) é necessário para equilibrar viés e variância.

</details>

#### Diferença entre Regressões Logísticas e SVM

| Aspecto | **Regressão Logística** | **Máquinas de Vetores de Suporte** |
|---|---|---|
| **Função objetivo** | Minimiza **log‑loss** (entropia cruzada). | Maximiza a **margem** enquanto minimiza **hinge‑loss**. |
| **Limite de decisão** | Encontra o **hiperplano de melhor ajuste** que modela _P(y\|x)_. | Encontra o **hiperplano de máxima margem** (maior espaço para os pontos mais próximos). |
| **Saída** | **Probabilística** – fornece probabilidades de classe calibradas via σ(w·x + b). | **Determinística** – retorna rótulos de classe; probabilidades precisam de trabalho extra (por exemplo, escalonamento de Platt). |
| **Regularização** | L2 (padrão) ou L1, equilibra diretamente o ajuste insuficiente/excessivo. | O parâmetro C troca a largura da margem por classificações erradas; os parâmetros do kernel adicionam complexidade. |
| **Kernels / Não‑linear** | A forma nativa é **linear**; a não linearidade é adicionada pela engenharia de características. | O **truque do kernel** embutido (RBF, polinomial, etc.) permite modelar limites complexos em espaço de alta dimensão. |
| **Escalabilidade** | Resolve uma otimização convexa em **O(nd)**; lida bem com n muito grande. | O treinamento pode ser **O(n²–n³)** em memória/tempo sem solucionadores especializados; menos amigável para n enorme. |
| **Interpretabilidade** | **Alta** – pesos mostram a influência das características; a razão de chances é intuitiva. | **Baixa** para kernels não lineares; vetores de suporte são esparsos, mas não fáceis de explicar. |
| **Sensibilidade a outliers** | Usa log‑loss suave → menos sensível. | Hinge‑loss com margem rígida pode ser **sensível**; margem suave (C) mitiga. |
| **Casos de uso típicos** | Avaliação de crédito, risco médico, testes A/B – onde **probabilidades e explicabilidade** importam. | Classificação de imagem/texto, bioinformática – onde **limites complexos** e **dados de alta dimensão** importam. |

* **Se você precisa de probabilidades calibradas, interpretabilidade ou opera em conjuntos de dados enormes — escolha Regressão Logística.**
* **Se você precisa de um modelo flexível que possa capturar relações não lineares sem engenharia manual de características — escolha SVM (com kernels).**
* Ambos otimizam objetivos convexos, então **mínimos globais são garantidos**, mas os kernels do SVM adicionam hiperparâmetros e custo computacional.

### Naive Bayes

Naive Bayes é uma família de **classificadores probabilísticos** baseados na aplicação do Teorema de Bayes com uma forte suposição de independência entre características. Apesar dessa suposição "ingênua", o Naive Bayes muitas vezes funciona surpreendentemente bem para certas aplicações, especialmente aquelas envolvendo dados textuais ou categóricos, como detecção de spam.

#### Teorema de Bayes

O teorema de Bayes é a base dos classificadores Naive Bayes. Ele relaciona as probabilidades condicionais e marginais de eventos aleatórios. A fórmula é:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Onde:
- `P(A|B)` é a probabilidade posterior da classe `A` dado o recurso `B`.
- `P(B|A)` é a verossimilhança do recurso `B` dado a classe `A`.
- `P(A)` é a probabilidade anterior da classe `A`.
- `P(B)` é a probabilidade anterior do recurso `B`.

Por exemplo, se quisermos classificar se um texto foi escrito por uma criança ou um adulto, podemos usar as palavras no texto como recursos. Com base em alguns dados iniciais, o classificador Naive Bayes calculará previamente as probabilidades de cada palavra estar em cada classe potencial (criança ou adulto). Quando um novo texto é fornecido, ele calculará a probabilidade de cada classe potencial dado as palavras no texto e escolherá a classe com a maior probabilidade.

Como você pode ver neste exemplo, o classificador Naive Bayes é muito simples e rápido, mas assume que os recursos são independentes, o que nem sempre é o caso em dados do mundo real.

#### Tipos de Classificadores Naive Bayes

Existem vários tipos de classificadores Naive Bayes, dependendo do tipo de dados e da distribuição dos recursos:
- **Gaussian Naive Bayes**: Assume que os recursos seguem uma distribuição Gaussiana (normal). É adequado para dados contínuos.
- **Multinomial Naive Bayes**: Assume que os recursos seguem uma distribuição multinomial. É adequado para dados discretos, como contagens de palavras em classificação de texto.
- **Bernoulli Naive Bayes**: Assume que os recursos são binários (0 ou 1). É adequado para dados binários, como presença ou ausência de palavras em classificação de texto.
- **Categorical Naive Bayes**: Assume que os recursos são variáveis categóricas. É adequado para dados categóricos, como classificar frutas com base em sua cor e forma.

#### **Características principais do Naive Bayes:**

-   **Tipo de Problema:** Classificação (binária ou multi-classe). Comumente usado para tarefas de classificação de texto em cibersegurança (spam, phishing, etc.).

-   **Interpretabilidade:** Média -- não é tão diretamente interpretável quanto uma árvore de decisão, mas pode-se inspecionar as probabilidades aprendidas (por exemplo, quais palavras são mais prováveis em e-mails de spam vs ham). A forma do modelo (probabilidades para cada recurso dado a classe) pode ser compreendida se necessário.

-   **Vantagens:** **Treinamento e previsão muito rápidos**, mesmo em grandes conjuntos de dados (linear no número de instâncias * número de recursos). Requer uma quantidade relativamente pequena de dados para estimar probabilidades de forma confiável, especialmente com a suavização adequada. Muitas vezes é surpreendentemente preciso como uma linha de base, especialmente quando os recursos contribuem independentemente com evidências para a classe. Funciona bem com dados de alta dimensão (por exemplo, milhares de recursos de texto). Nenhuma afinação complexa é necessária além de definir um parâmetro de suavização.

-   **Limitações:** A suposição de independência pode limitar a precisão se os recursos estiverem altamente correlacionados. Por exemplo, em dados de rede, recursos como `src_bytes` e `dst_bytes` podem estar correlacionados; o Naive Bayes não capturará essa interação. À medida que o tamanho dos dados cresce muito, modelos mais expressivos (como ensembles ou redes neurais) podem superar o NB aprendendo dependências de recursos. Além disso, se uma certa combinação de recursos for necessária para identificar um ataque (não apenas recursos individuais de forma independente), o NB terá dificuldades.

> [!TIP]
> *Casos de uso em cibersegurança:* O uso clássico é **detecção de spam** -- o Naive Bayes foi o núcleo dos primeiros filtros de spam, usando as frequências de certos tokens (palavras, frases, endereços IP) para calcular a probabilidade de um e-mail ser spam. Também é usado na **detecção de e-mails de phishing** e **classificação de URLs**, onde a presença de certas palavras-chave ou características (como "login.php" em uma URL, ou `@` em um caminho de URL) contribui para a probabilidade de phishing. Na análise de malware, pode-se imaginar um classificador Naive Bayes que usa a presença de certas chamadas de API ou permissões em software para prever se é malware. Embora algoritmos mais avançados frequentemente tenham um desempenho melhor, o Naive Bayes continua sendo uma boa linha de base devido à sua velocidade e simplicidade.

<details>
<summary>Exemplo -- Naive Bayes para Detecção de Phishing:</summary>
Para demonstrar o Naive Bayes, usaremos o Gaussian Naive Bayes no conjunto de dados de intrusão NSL-KDD (com rótulos binários). O Gaussian NB tratará cada recurso como seguindo uma distribuição normal por classe. Esta é uma escolha aproximada, uma vez que muitos recursos de rede são discretos ou altamente enviesados, mas mostra como se aplicaria o NB a dados de recursos contínuos. Também poderíamos escolher o Bernoulli NB em um conjunto de dados de recursos binários (como um conjunto de alertas acionados), mas permaneceremos com o NSL-KDD aqui para continuidade.
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
Este código treina um classificador Naive Bayes para detectar ataques. Naive Bayes calculará coisas como `P(service=http | Attack)` e `P(Service=http | Normal)` com base nos dados de treinamento, assumindo independência entre as características. Ele então usará essas probabilidades para classificar novas conexões como normais ou ataques com base nas características observadas. O desempenho do NB no NSL-KDD pode não ser tão alto quanto modelos mais avançados (já que a independência das características é violada), mas geralmente é decente e vem com o benefício de extrema velocidade. Em cenários como filtragem de e-mails em tempo real ou triagem inicial de URLs, um modelo Naive Bayes pode rapidamente sinalizar casos obviamente maliciosos com baixo uso de recursos.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors é um dos algoritmos de aprendizado de máquina mais simples. É um método **não paramétrico, baseado em instâncias** que faz previsões com base na similaridade a exemplos no conjunto de treinamento. A ideia para classificação é: para classificar um novo ponto de dados, encontrar os **k** pontos mais próximos nos dados de treinamento (seus "vizinhos mais próximos") e atribuir a classe majoritária entre esses vizinhos. "Proximidade" é definida por uma métrica de distância, tipicamente a distância euclidiana para dados numéricos (outras distâncias podem ser usadas para diferentes tipos de características ou problemas).

K-NN requer *nenhum treinamento explícito* -- a fase de "treinamento" é apenas armazenar o conjunto de dados. Todo o trabalho acontece durante a consulta (previsão): o algoritmo deve calcular distâncias do ponto de consulta para todos os pontos de treinamento para encontrar os mais próximos. Isso torna o tempo de previsão **linear no número de amostras de treinamento**, o que pode ser custoso para grandes conjuntos de dados. Devido a isso, k-NN é mais adequado para conjuntos de dados menores ou cenários onde você pode trocar memória e velocidade por simplicidade.

Apesar de sua simplicidade, k-NN pode modelar limites de decisão muito complexos (já que efetivamente o limite de decisão pode ter qualquer forma ditada pela distribuição de exemplos). Ele tende a ter um bom desempenho quando o limite de decisão é muito irregular e você tem muitos dados -- essencialmente permitindo que os dados "falem por si mesmos". No entanto, em altas dimensões, as métricas de distância podem se tornar menos significativas (maldição da dimensionalidade), e o método pode ter dificuldades, a menos que você tenha um grande número de amostras.

*Casos de uso em cibersegurança:* k-NN foi aplicado à detecção de anomalias -- por exemplo, um sistema de detecção de intrusões pode rotular um evento de rede como malicioso se a maioria de seus vizinhos mais próximos (eventos anteriores) forem maliciosos. Se o tráfego normal formar clusters e os ataques forem outliers, uma abordagem K-NN (com k=1 ou k pequeno) essencialmente faz uma **detecção de anomalias por vizinho mais próximo**. K-NN também foi usado para classificar famílias de malware por vetores de características binárias: um novo arquivo pode ser classificado como uma certa família de malware se estiver muito próximo (no espaço de características) de instâncias conhecidas daquela família. Na prática, k-NN não é tão comum quanto algoritmos mais escaláveis, mas é conceitualmente simples e às vezes usado como uma linha de base ou para problemas em pequena escala.

#### **Características principais do k-NN:**

-   **Tipo de Problema:** Classificação (e variantes de regressão existem). É um método de *aprendizado preguiçoso* -- sem ajuste de modelo explícito.

-   **Interpretabilidade:** Baixa a média -- não há modelo global ou explicação concisa, mas pode-se interpretar resultados observando os vizinhos mais próximos que influenciaram uma decisão (por exemplo, "este fluxo de rede foi classificado como malicioso porque é semelhante a esses 3 fluxos maliciosos conhecidos"). Assim, as explicações podem ser baseadas em exemplos.

-   **Vantagens:** Muito simples de implementar e entender. Não faz suposições sobre a distribuição dos dados (não paramétrico). Pode lidar naturalmente com problemas de múltiplas classes. É **adaptativo** no sentido de que os limites de decisão podem ser muito complexos, moldados pela distribuição dos dados.

-   **Limitações:** A previsão pode ser lenta para grandes conjuntos de dados (deve calcular muitas distâncias). Intensivo em memória -- armazena todos os dados de treinamento. O desempenho degrada em espaços de características de alta dimensão porque todos os pontos tendem a se tornar quase equidistantes (tornando o conceito de "mais próximo" menos significativo). É necessário escolher *k* (número de vizinhos) de forma apropriada -- k muito pequeno pode ser ruidoso, k muito grande pode incluir pontos irrelevantes de outras classes. Além disso, as características devem ser escaladas adequadamente porque os cálculos de distância são sensíveis à escala.

<details>
<summary>Exemplo -- k-NN para Detecção de Phishing:</summary>

Usaremos novamente o NSL-KDD (classificação binária). Como k-NN é computacionalmente pesado, usaremos um subconjunto dos dados de treinamento para mantê-lo viável nesta demonstração. Escolheremos, digamos, 20.000 amostras de treinamento do total de 125k, e usaremos k=5 vizinhos. Após o treinamento (na verdade, apenas armazenando os dados), avaliaremos no conjunto de teste. Também escalaremos as características para o cálculo de distância para garantir que nenhuma característica única domine devido à escala.
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
O modelo k-NN classificará uma conexão observando as 5 conexões mais próximas no subconjunto do conjunto de treinamento. Se, por exemplo, 4 desses vizinhos forem ataques (anomalias) e 1 for normal, a nova conexão será classificada como um ataque. O desempenho pode ser razoável, embora muitas vezes não tão alto quanto um Random Forest ou SVM bem ajustado nos mesmos dados. No entanto, o k-NN pode brilhar às vezes quando as distribuições de classes são muito irregulares e complexas -- efetivamente usando uma busca baseada em memória. Em cibersegurança, o k-NN (com k=1 ou pequeno k) pode ser usado para detecção de padrões de ataque conhecidos por exemplo, ou como um componente em sistemas mais complexos (por exemplo, para agrupamento e, em seguida, classificação com base na associação ao grupo).

### Gradient Boosting Machines (por exemplo, XGBoost)

As Gradient Boosting Machines estão entre os algoritmos mais poderosos para dados estruturados. **Gradient boosting** refere-se à técnica de construir um conjunto de aprendizes fracos (geralmente árvores de decisão) de maneira sequencial, onde cada novo modelo corrige os erros do conjunto anterior. Ao contrário do bagging (Random Forests), que constrói árvores em paralelo e as média, o boosting constrói árvores *uma a uma*, cada uma focando mais nas instâncias que as árvores anteriores previram incorretamente.

As implementações mais populares nos últimos anos são **XGBoost**, **LightGBM** e **CatBoost**, todas bibliotecas de árvores de decisão de boosting por gradiente (GBDT). Elas têm sido extremamente bem-sucedidas em competições e aplicações de aprendizado de máquina, frequentemente **alcançando desempenho de ponta em conjuntos de dados tabulares**. Em cibersegurança, pesquisadores e profissionais têm usado árvores de boosting por gradiente para tarefas como **detecção de malware** (usando características extraídas de arquivos ou comportamento em tempo de execução) e **detecção de intrusão em redes**. Por exemplo, um modelo de boosting por gradiente pode combinar muitas regras fracas (árvores) como "se muitos pacotes SYN e porta incomum -> provável varredura" em um detector composto forte que leva em conta muitos padrões sutis.

Por que as árvores de boosting são tão eficazes? Cada árvore na sequência é treinada nos *erros residuais* (gradientes) das previsões do conjunto atual. Dessa forma, o modelo gradualmente **"impulsiona"** as áreas onde é fraco. O uso de árvores de decisão como aprendizes base significa que o modelo final pode capturar interações complexas e relações não lineares. Além disso, o boosting tem uma forma de regularização embutida: ao adicionar muitas árvores pequenas (e usar uma taxa de aprendizado para escalar suas contribuições), geralmente generaliza bem sem grandes sobreajustes, desde que parâmetros adequados sejam escolhidos.

#### **Características principais do Gradient Boosting:**

-   **Tipo de Problema:** Principalmente classificação e regressão. Em segurança, geralmente classificação (por exemplo, classificar binariamente uma conexão ou arquivo). Lida com problemas binários, multiclasses (com perda apropriada) e até mesmo problemas de classificação.

-   **Interpretabilidade:** Baixa a média. Embora uma única árvore de boosting seja pequena, um modelo completo pode ter centenas de árvores, o que não é interpretável para humanos como um todo. No entanto, como o Random Forest, pode fornecer pontuações de importância de características, e ferramentas como SHAP (SHapley Additive exPlanations) podem ser usadas para interpretar previsões individuais até certo ponto.

-   **Vantagens:** Frequentemente o **algoritmo de melhor desempenho** para dados estruturados/tabulares. Pode detectar padrões e interações complexas. Tem muitos parâmetros de ajuste (número de árvores, profundidade das árvores, taxa de aprendizado, termos de regularização) para personalizar a complexidade do modelo e prevenir sobreajuste. Implementações modernas são otimizadas para velocidade (por exemplo, o XGBoost usa informações de gradiente de segunda ordem e estruturas de dados eficientes). Tende a lidar melhor com dados desbalanceados quando combinado com funções de perda apropriadas ou ajustando pesos de amostra.

-   **Limitações:** Mais complexo de ajustar do que modelos mais simples; o treinamento pode ser lento se as árvores forem profundas ou o número de árvores for grande (embora ainda geralmente mais rápido do que treinar uma rede neural profunda comparável nos mesmos dados). O modelo pode sobreajustar se não for ajustado (por exemplo, muitas árvores profundas com regularização insuficiente). Devido a muitos hiperparâmetros, usar boosting por gradiente de forma eficaz pode exigir mais expertise ou experimentação. Além disso, como métodos baseados em árvores, não lida inerentemente com dados esparsos de alta dimensão tão eficientemente quanto modelos lineares ou Naive Bayes (embora ainda possa ser aplicado, por exemplo, em classificação de texto, mas pode não ser a primeira escolha sem engenharia de características).

> [!TIP]
> *Casos de uso em cibersegurança:* Quase em qualquer lugar onde uma árvore de decisão ou random forest poderia ser usada, um modelo de boosting por gradiente pode alcançar melhor precisão. Por exemplo, as competições de **detecção de malware da Microsoft** viram um uso intenso do XGBoost em características engenheiradas de arquivos binários. A pesquisa em **detecção de intrusão em redes** frequentemente relata os melhores resultados com GBDTs (por exemplo, XGBoost nos conjuntos de dados CIC-IDS2017 ou UNSW-NB15). Esses modelos podem levar uma ampla gama de características (tipos de protocolo, frequência de certos eventos, características estatísticas do tráfego, etc.) e combiná-las para detectar ameaças. Na detecção de phishing, o boosting por gradiente pode combinar características lexicais de URLs, características de reputação de domínio e características de conteúdo da página para alcançar uma precisão muito alta. A abordagem de conjunto ajuda a cobrir muitos casos extremos e sutilezas nos dados.

<details>
<summary>Exemplo -- XGBoost para Detecção de Phishing:</summary>
Usaremos um classificador de boosting por gradiente no conjunto de dados de phishing. Para manter as coisas simples e autossuficientes, usaremos `sklearn.ensemble.GradientBoostingClassifier` (que é uma implementação mais lenta, mas direta). Normalmente, alguém poderia usar as bibliotecas `xgboost` ou `lightgbm` para melhor desempenho e recursos adicionais. Treinaremos o modelo e o avaliaremos de maneira semelhante ao que foi feito antes.
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
O modelo de gradient boosting provavelmente alcançará uma precisão e AUC muito altas neste conjunto de dados de phishing (frequentemente, esses modelos podem exceder 95% de precisão com o ajuste adequado em tais dados, como visto na literatura. Isso demonstra por que os GBDTs são considerados *"o modelo de ponta para conjuntos de dados tabulares"* -- eles frequentemente superam algoritmos mais simples ao capturar padrões complexos. Em um contexto de cibersegurança, isso pode significar detectar mais sites de phishing ou ataques com menos erros. Claro, deve-se ter cautela quanto ao overfitting -- normalmente usaríamos técnicas como validação cruzada e monitorar o desempenho em um conjunto de validação ao desenvolver tal modelo para implantação.

</details>

### Combinando Modelos: Aprendizado em Conjunto e Stacking

O aprendizado em conjunto é uma estratégia de **combinar múltiplos modelos** para melhorar o desempenho geral. Já vimos métodos de conjunto específicos: Random Forest (um conjunto de árvores via bagging) e Gradient Boosting (um conjunto de árvores via boosting sequencial). Mas os conjuntos também podem ser criados de outras maneiras, como **conjuntos de votação** ou **generalização empilhada (stacking)**. A ideia principal é que diferentes modelos podem capturar padrões diferentes ou ter fraquezas diferentes; ao combiná-los, podemos **compensar os erros de cada modelo com as forças de outro**.

-   **Conjunto de Votação:** Em um classificador de votação simples, treinamos múltiplos modelos diversos (digamos, uma regressão logística, uma árvore de decisão e um SVM) e fazemos com que votem na previsão final (voto da maioria para classificação). Se pesarmos os votos (por exemplo, maior peso para modelos mais precisos), é um esquema de votação ponderada. Isso geralmente melhora o desempenho quando os modelos individuais são razoavelmente bons e independentes -- o conjunto reduz o risco de erro de um modelo individual, já que outros podem corrigi-lo. É como ter um painel de especialistas em vez de uma única opinião.

-   **Stacking (Conjunto Empilhado):** O stacking vai um passo além. Em vez de um voto simples, ele treina um **meta-modelo** para **aprender a melhor combinar as previsões** dos modelos base. Por exemplo, você treina 3 classificadores diferentes (aprendizes base), e então alimenta suas saídas (ou probabilidades) como características em um meta-classificador (geralmente um modelo simples como regressão logística) que aprende a maneira ideal de misturá-los. O meta-modelo é treinado em um conjunto de validação ou via validação cruzada para evitar overfitting. O stacking pode frequentemente superar a votação simples ao aprender *quais modelos confiar mais em quais circunstâncias*. Em cibersegurança, um modelo pode ser melhor em detectar varreduras de rede enquanto outro é melhor em detectar beaconing de malware; um modelo de stacking poderia aprender a confiar em cada um de forma apropriada.

Conjuntos, seja por votação ou stacking, tendem a **aumentar a precisão** e robustez. A desvantagem é a complexidade aumentada e, às vezes, a interpretabilidade reduzida (embora algumas abordagens de conjunto, como a média de árvores de decisão, ainda possam fornecer alguma visão, por exemplo, importância de características). Na prática, se as restrições operacionais permitirem, usar um conjunto pode levar a taxas de detecção mais altas. Muitas soluções vencedoras em desafios de cibersegurança (e competições do Kaggle em geral) usam técnicas de conjunto para extrair o último pedaço de desempenho.

<details>
<summary>Exemplo -- Conjunto de Votação para Detecção de Phishing:</summary>
Para ilustrar o stacking de modelos, vamos combinar alguns dos modelos que discutimos no conjunto de dados de phishing. Usaremos uma regressão logística, uma árvore de decisão e um k-NN como aprendizes base, e usaremos um Random Forest como um meta-aprendiz para agregar suas previsões. O meta-aprendiz será treinado nas saídas dos aprendizes base (usando validação cruzada no conjunto de treinamento). Esperamos que o modelo empilhado tenha um desempenho tão bom quanto ou ligeiramente melhor do que os modelos individuais.
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
O ensemble empilhado aproveita as forças complementares dos modelos base. Por exemplo, a regressão logística pode lidar com aspectos lineares dos dados, a árvore de decisão pode capturar interações específicas semelhantes a regras, e o k-NN pode se destacar em vizinhanças locais do espaço de características. O meta-modelo (aqui um random forest) pode aprender a ponderar essas entradas. As métricas resultantes geralmente mostram uma melhoria (mesmo que leve) em relação às métricas de qualquer modelo único. No nosso exemplo de phishing, se a logística sozinha tivesse um F1 de, digamos, 0.95 e a árvore 0.94, o empilhamento poderia alcançar 0.96 ao captar onde cada modelo erra.

Métodos de ensemble como este demonstram o princípio de que *"combinar múltiplos modelos geralmente leva a uma melhor generalização"*. Em cibersegurança, isso pode ser implementado tendo múltiplos motores de detecção (um pode ser baseado em regras, um em aprendizado de máquina, um baseado em anomalias) e, em seguida, uma camada que agrega seus alertas -- efetivamente uma forma de ensemble -- para tomar uma decisão final com maior confiança. Ao implantar tais sistemas, deve-se considerar a complexidade adicional e garantir que o ensemble não se torne difícil de gerenciar ou explicar. Mas, do ponto de vista da precisão, ensembles e empilhamento são ferramentas poderosas para melhorar o desempenho do modelo.

</details>


## Referências

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
