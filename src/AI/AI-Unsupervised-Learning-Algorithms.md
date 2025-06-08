# Algoritmos de Aprendizado Não Supervisionado

{{#include ../banners/hacktricks-training.md}}

## Aprendizado Não Supervisionado

O aprendizado não supervisionado é um tipo de aprendizado de máquina onde o modelo é treinado com dados sem respostas rotuladas. O objetivo é encontrar padrões, estruturas ou relacionamentos dentro dos dados. Ao contrário do aprendizado supervisionado, onde o modelo aprende a partir de exemplos rotulados, os algoritmos de aprendizado não supervisionado trabalham com dados não rotulados. O aprendizado não supervisionado é frequentemente utilizado para tarefas como agrupamento, redução de dimensionalidade e detecção de anomalias. Ele pode ajudar a descobrir padrões ocultos nos dados, agrupar itens semelhantes ou reduzir a complexidade dos dados enquanto preserva suas características essenciais.

### Agrupamento K-Means

K-Means é um algoritmo de agrupamento baseado em centróides que particiona os dados em K clusters, atribuindo cada ponto ao centroide do cluster mais próximo. O algoritmo funciona da seguinte forma:
1. **Inicialização**: Escolha K centros de cluster iniciais (centróides), frequentemente aleatoriamente ou por meio de métodos mais inteligentes como k-means++.
2. **Atribuição**: Atribua cada ponto de dados ao centróide mais próximo com base em uma métrica de distância (por exemplo, distância euclidiana).
3. **Atualização**: Recalcule os centróides tomando a média de todos os pontos de dados atribuídos a cada cluster.
4. **Repetir**: As etapas 2–3 são repetidas até que as atribuições de cluster se estabilizem (os centróides não se movem significativamente).

> [!TIP]
> *Casos de uso em cibersegurança:* K-Means é utilizado para detecção de intrusões agrupando eventos de rede. Por exemplo, pesquisadores aplicaram K-Means ao conjunto de dados de intrusão KDD Cup 99 e descobriram que ele particionava efetivamente o tráfego em clusters normais vs. de ataque. Na prática, analistas de segurança podem agrupar entradas de log ou dados de comportamento do usuário para encontrar grupos de atividade semelhante; quaisquer pontos que não pertencem a um cluster bem formado podem indicar anomalias (por exemplo, uma nova variante de malware formando seu próprio pequeno cluster). K-Means também pode ajudar na classificação de famílias de malware agrupando binários com base em perfis de comportamento ou vetores de características.

#### Seleção de K
O número de clusters (K) é um hiperparâmetro que precisa ser definido antes de executar o algoritmo. Técnicas como o Método do Cotovelo ou a Pontuação de Silhueta podem ajudar a determinar um valor apropriado para K, avaliando o desempenho do agrupamento:

- **Método do Cotovelo**: Plote a soma das distâncias quadradas de cada ponto ao seu centróide de cluster atribuído como uma função de K. Procure um ponto de "cotovelo" onde a taxa de diminuição muda abruptamente, indicando um número adequado de clusters.
- **Pontuação de Silhueta**: Calcule a pontuação de silhueta para diferentes valores de K. Uma pontuação de silhueta mais alta indica clusters melhor definidos.

#### Suposições e Limitações

K-Means assume que **os clusters são esféricos e de tamanho igual**, o que pode não ser verdade para todos os conjuntos de dados. Ele é sensível à colocação inicial dos centróides e pode convergir para mínimos locais. Além disso, K-Means não é adequado para conjuntos de dados com densidades variáveis ou formas não globulares e características com diferentes escalas. Etapas de pré-processamento, como normalização ou padronização, podem ser necessárias para garantir que todas as características contribuam igualmente para os cálculos de distância.

<details>
<summary>Exemplo -- Agrupando Eventos de Rede
</summary>
Abaixo, simulamos dados de tráfego de rede e usamos K-Means para agrupá-los. Suponha que temos eventos com características como duração da conexão e contagem de bytes. Criamos 3 clusters de tráfego "normal" e 1 pequeno cluster representando um padrão de ataque. Em seguida, executamos K-Means para ver se ele os separa.
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
Neste exemplo, o K-Means deve encontrar 4 clusters. O pequeno cluster de ataque (com duração incomumente alta ~200) idealmente formará seu próprio cluster, dada sua distância dos clusters normais. Imprimimos os tamanhos e centros dos clusters para interpretar os resultados. Em um cenário real, poderia-se rotular o cluster com poucos pontos como potenciais anomalias ou inspecionar seus membros em busca de atividade maliciosa.

### Agrupamento Hierárquico

O agrupamento hierárquico constrói uma hierarquia de clusters usando uma abordagem de baixo para cima (aglomerativa) ou de cima para baixo (divisiva):

1. **Aglomerativa (De Baixo para Cima)**: Começa com cada ponto de dados como um cluster separado e mescla iterativamente os clusters mais próximos até que um único cluster permaneça ou um critério de parada seja atendido.
2. **Divisiva (De Cima para Baixo)**: Começa com todos os pontos de dados em um único cluster e divide iterativamente os clusters até que cada ponto de dados seja seu próprio cluster ou um critério de parada seja atendido.

O agrupamento aglomerativo requer uma definição de distância entre clusters e um critério de ligação para decidir quais clusters mesclar. Métodos de ligação comuns incluem ligação simples (distância dos pontos mais próximos entre dois clusters), ligação completa (distância dos pontos mais distantes), ligação média, etc., e a métrica de distância é frequentemente Euclidiana. A escolha da ligação afeta a forma dos clusters produzidos. Não há necessidade de pré-especificar o número de clusters K; você pode "cortar" o dendrograma em um nível escolhido para obter o número desejado de clusters.

O agrupamento hierárquico produz um dendrograma, uma estrutura em forma de árvore que mostra as relações entre clusters em diferentes níveis de granularidade. O dendrograma pode ser cortado em um nível desejado para obter um número específico de clusters.

> [!TIP]
> *Casos de uso em cibersegurança:* O agrupamento hierárquico pode organizar eventos ou entidades em uma árvore para identificar relações. Por exemplo, na análise de malware, o agrupamento aglomerativo poderia agrupar amostras por similaridade comportamental, revelando uma hierarquia de famílias e variantes de malware. Na segurança de rede, pode-se agrupar fluxos de tráfego IP e usar o dendrograma para ver subgrupos de tráfego (por exemplo, por protocolo, depois por comportamento). Como você não precisa escolher K antecipadamente, é útil ao explorar novos dados para os quais o número de categorias de ataque é desconhecido.

#### Suposições e Limitações

O agrupamento hierárquico não assume uma forma de cluster particular e pode capturar clusters aninhados. É útil para descobrir taxonomias ou relações entre grupos (por exemplo, agrupando malware por subgrupos familiares). É determinístico (sem problemas de inicialização aleatória). Uma vantagem chave é o dendrograma, que fornece uma visão da estrutura de agrupamento dos dados em todas as escalas – analistas de segurança podem decidir um corte apropriado para identificar clusters significativos. No entanto, é computacionalmente caro (tipicamente $O(n^2)$ de tempo ou pior para implementações ingênuas) e não viável para conjuntos de dados muito grandes. Também é um procedimento ganancioso – uma vez que uma mesclagem ou divisão é feita, não pode ser desfeita, o que pode levar a clusters subótimos se um erro ocorrer cedo. Outliers também podem afetar algumas estratégias de ligação (a ligação simples pode causar o efeito de "encadeamento", onde clusters se conectam via outliers).

<details>
<summary>Exemplo -- Agrupamento Aglomerativo de Eventos
</summary>

Reutilizaremos os dados sintéticos do exemplo do K-Means (3 clusters normais + 1 cluster de ataque) e aplicaremos o agrupamento aglomerativo. Em seguida, ilustramos como obter um dendrograma e rótulos de clusters.
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

### DBSCAN (Agrupamento Espacial Baseado em Densidade de Aplicações com Ruído)

DBSCAN é um algoritmo de agrupamento baseado em densidade que agrupa pontos que estão próximos uns dos outros, enquanto marca pontos em regiões de baixa densidade como outliers. É particularmente útil para conjuntos de dados com densidades variadas e formas não esféricas.

DBSCAN funciona definindo dois parâmetros:
- **Epsilon (ε)**: A distância máxima entre dois pontos para serem considerados parte do mesmo cluster.
- **MinPts**: O número mínimo de pontos necessários para formar uma região densa (ponto central).

DBSCAN identifica pontos centrais, pontos de borda e pontos de ruído:
- **Ponto Central**: Um ponto com pelo menos MinPts vizinhos dentro da distância ε.
- **Ponto de Borda**: Um ponto que está dentro da distância ε de um ponto central, mas tem menos de MinPts vizinhos.
- **Ponto de Ruído**: Um ponto que não é nem um ponto central nem um ponto de borda.

O agrupamento prossegue escolhendo um ponto central não visitado, marcando-o como um novo cluster, e então adicionando recursivamente todos os pontos acessíveis por densidade a partir dele (pontos centrais e seus vizinhos, etc.). Pontos de borda são adicionados ao cluster de um ponto central próximo. Após expandir todos os pontos acessíveis, o DBSCAN passa para outro ponto central não visitado para iniciar um novo cluster. Pontos que não foram alcançados por nenhum ponto central permanecem rotulados como ruído.

> [!TIP]
> *Casos de uso em cibersegurança:* DBSCAN é útil para detecção de anomalias no tráfego de rede. Por exemplo, a atividade normal do usuário pode formar um ou mais clusters densos no espaço de características, enquanto comportamentos de ataque novos aparecem como pontos dispersos que o DBSCAN rotulará como ruído (outliers). Ele tem sido usado para agrupar registros de fluxo de rede, onde pode detectar varreduras de portas ou tráfego de negação de serviço como regiões esparsas de pontos. Outra aplicação é agrupar variantes de malware: se a maioria das amostras se agrupar por famílias, mas algumas não se encaixam em lugar nenhum, essas poucas podem ser malware de dia zero. A capacidade de sinalizar ruído significa que as equipes de segurança podem se concentrar em investigar esses outliers.

#### Suposições e Limitações

**Suposições & Forças:**: O DBSCAN não assume clusters esféricos – ele pode encontrar clusters de formas arbitrárias (mesmo clusters em cadeia ou adjacentes). Ele determina automaticamente o número de clusters com base na densidade dos dados e pode identificar efetivamente outliers como ruído. Isso o torna poderoso para dados do mundo real com formas irregulares e ruído. É robusto a outliers (diferente do K-Means, que os força em clusters). Funciona bem quando os clusters têm densidade aproximadamente uniforme.

**Limitações**: O desempenho do DBSCAN depende da escolha de valores apropriados para ε e MinPts. Ele pode ter dificuldades com dados que possuem densidades variadas – um único ε não pode acomodar clusters densos e esparsos. Se ε for muito pequeno, rotula a maioria dos pontos como ruído; se for muito grande, os clusters podem se fundir incorretamente. Além disso, o DBSCAN pode ser ineficiente em conjuntos de dados muito grandes (naïve $O(n^2)$, embora a indexação espacial possa ajudar). Em espaços de características de alta dimensão, o conceito de “distância dentro de ε” pode se tornar menos significativo (a maldição da dimensionalidade), e o DBSCAN pode precisar de ajuste cuidadoso de parâmetros ou pode falhar em encontrar clusters intuitivos. Apesar disso, extensões como HDBSCAN abordam algumas questões (como densidade variável).

<details>
<summary>Exemplo -- Agrupamento com Ruído
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
Neste trecho, ajustamos `eps` e `min_samples` para se adequar à escala dos nossos dados (15.0 em unidades de características, e exigindo 5 pontos para formar um cluster). O DBSCAN deve encontrar 2 clusters (os clusters de tráfego normal) e sinalizar os 5 outliers injetados como ruído. Nós exibimos o número de clusters em relação aos pontos de ruído para verificar isso. Em um cenário real, pode-se iterar sobre ε (usando uma heurística de gráfico de distância k para escolher ε) e MinPts (geralmente definido em torno da dimensionalidade dos dados + 1 como uma regra prática) para encontrar resultados de clustering estáveis. A capacidade de rotular explicitamente o ruído ajuda a separar dados de ataque potenciais para análise posterior.

</details>

### Análise de Componentes Principais (PCA)

PCA é uma técnica para **redução de dimensionalidade** que encontra um novo conjunto de eixos ortogonais (componentes principais) que capturam a máxima variância nos dados. Em termos simples, o PCA rotaciona e projeta os dados em um novo sistema de coordenadas de modo que o primeiro componente principal (PC1) explique a maior variância possível, o segundo PC (PC2) explique a maior variância ortogonal ao PC1, e assim por diante. Matematicamente, o PCA calcula os autovetores da matriz de covariância dos dados – esses autovetores são as direções dos componentes principais, e os autovalores correspondentes indicam a quantidade de variância explicada por cada um. É frequentemente usado para extração de características, visualização e redução de ruído.

Note que isso é útil se as dimensões do conjunto de dados contêm **dependências ou correlações lineares significativas**.

O PCA funciona identificando os componentes principais dos dados, que são as direções de máxima variância. Os passos envolvidos no PCA são:
1. **Padronização**: Centralizar os dados subtraindo a média e escalando para variância unitária.
2. **Matriz de Covariância**: Calcular a matriz de covariância dos dados padronizados para entender as relações entre as características.
3. **Decomposição de Autovalores**: Realizar a decomposição de autovalores na matriz de covariância para obter os autovalores e autovetores.
4. **Selecionar Componentes Principais**: Classificar os autovalores em ordem decrescente e selecionar os K autovetores correspondentes aos maiores autovalores. Esses autovetores formam o novo espaço de características.
5. **Transformar Dados**: Projetar os dados originais no novo espaço de características usando os componentes principais selecionados.
O PCA é amplamente utilizado para visualização de dados, redução de ruído e como um passo de pré-processamento para outros algoritmos de aprendizado de máquina. Ele ajuda a reduzir a dimensionalidade dos dados enquanto retém sua estrutura essencial.

#### Autovalores e Autovetores

Um autovalor é um escalar que indica a quantidade de variância capturada pelo seu autovetor correspondente. Um autovetor representa uma direção no espaço de características ao longo da qual os dados variam mais.

Imagine que A é uma matriz quadrada, e v é um vetor não nulo tal que: `A * v = λ * v`
onde:
- A é uma matriz quadrada como [ [1, 2], [2, 1]] (por exemplo, matriz de covariância)
- v é um autovetor (por exemplo, [1, 1])

Então, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` que será o autovalor λ multiplicado pelo autovetor v, fazendo com que o autovalor λ = 3.

#### Autovalores e Autovetores em PCA

Vamos explicar isso com um exemplo. Imagine que você tem um conjunto de dados com muitas imagens em escala de cinza de rostos de 100x100 pixels. Cada pixel pode ser considerado uma característica, então você tem 10.000 características por imagem (ou um vetor de 10.000 componentes por imagem). Se você quiser reduzir a dimensionalidade desse conjunto de dados usando PCA, você seguiria estes passos:

1. **Padronização**: Centralizar os dados subtraindo a média de cada característica (pixel) do conjunto de dados.
2. **Matriz de Covariância**: Calcular a matriz de covariância dos dados padronizados, que captura como as características (pixels) variam juntas.
- Note que a covariância entre duas variáveis (pixels neste caso) indica o quanto elas mudam juntas, então a ideia aqui é descobrir quais pixels tendem a aumentar ou diminuir juntos com uma relação linear.
- Por exemplo, se o pixel 1 e o pixel 2 tendem a aumentar juntos, a covariância entre eles será positiva.
- A matriz de covariância será uma matriz 10.000x10.000 onde cada entrada representa a covariância entre dois pixels.
3. **Resolver a equação do autovalor**: A equação do autovalor a ser resolvida é `C * v = λ * v` onde C é a matriz de covariância, v é o autovetor, e λ é o autovalor. Pode ser resolvida usando métodos como:
- **Decomposição de Autovalores**: Realizar a decomposição de autovalores na matriz de covariância para obter os autovalores e autovetores.
- **Decomposição em Valores Singulares (SVD)**: Alternativamente, você pode usar SVD para decompor a matriz de dados em valores e vetores singulares, que também podem gerar os componentes principais.
4. **Selecionar Componentes Principais**: Classificar os autovalores em ordem decrescente e selecionar os K autovetores correspondentes aos maiores autovalores. Esses autovetores representam as direções de máxima variância nos dados.

> [!TIP]
> *Casos de uso em cibersegurança:* Um uso comum do PCA em segurança é a redução de características para detecção de anomalias. Por exemplo, um sistema de detecção de intrusões com mais de 40 métricas de rede (como características do NSL-KDD) pode usar PCA para reduzir a um punhado de componentes, resumindo os dados para visualização ou alimentação em algoritmos de clustering. Analistas podem plotar o tráfego de rede no espaço dos dois primeiros componentes principais para ver se os ataques se separam do tráfego normal. O PCA também pode ajudar a eliminar características redundantes (como bytes enviados vs. bytes recebidos se estiverem correlacionados) para tornar os algoritmos de detecção mais robustos e rápidos.

#### Suposições e Limitações

O PCA assume que **os eixos principais de variância são significativos** – é um método linear, portanto captura correlações lineares nos dados. É não supervisionado, pois usa apenas a covariância das características. As vantagens do PCA incluem redução de ruído (componentes de pequena variância geralmente correspondem a ruído) e decorrelação das características. É computacionalmente eficiente para dimensões moderadamente altas e frequentemente um passo de pré-processamento útil para outros algoritmos (para mitigar a maldição da dimensionalidade). Uma limitação é que o PCA é limitado a relações lineares – não capturará estruturas complexas não lineares (enquanto autoencoders ou t-SNE podem). Além disso, os componentes do PCA podem ser difíceis de interpretar em termos de características originais (são combinações de características originais). Na cibersegurança, deve-se ter cautela: um ataque que causa apenas uma mudança sutil em uma característica de baixa variância pode não aparecer nos PCs principais (já que o PCA prioriza a variância, não necessariamente a "interessância").

<details>
<summary>Exemplo -- Reduzindo Dimensões de Dados de Rede
</summary>

Suponha que temos logs de conexão de rede com múltiplas características (por exemplo, durações, bytes, contagens). Vamos gerar um conjunto de dados sintético de 4 dimensões (com alguma correlação entre as características) e usar PCA para reduzi-lo a 2 dimensões para visualização ou análise posterior.
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
Aqui, pegamos os clusters de tráfego normal anteriores e estendemos cada ponto de dados com duas características adicionais (pacotes e erros) que se correlacionam com bytes e duração. PCA é então usado para comprimir as 4 características em 2 componentes principais. Imprimimos a razão de variância explicada, que pode mostrar que, digamos, >95% da variância é capturada por 2 componentes (o que significa pouca perda de informação). A saída também mostra a forma dos dados reduzindo de (1500, 4) para (1500, 2). Os primeiros pontos no espaço PCA são dados como exemplo. Na prática, pode-se plotar data_2d para verificar visualmente se os clusters são distinguíveis. Se uma anomalia estiver presente, pode-se vê-la como um ponto afastado do cluster principal no espaço PCA. Assim, PCA ajuda a destilar dados complexos em uma forma gerenciável para interpretação humana ou como entrada para outros algoritmos.

</details>


### Modelos de Mistura Gaussiana (GMM)

Um Modelo de Mistura Gaussiana assume que os dados são gerados a partir de uma mistura de **várias distribuições Gaussianas (normais) com parâmetros desconhecidos**. Em essência, é um modelo de clustering probabilístico: tenta atribuir suavemente cada ponto a um dos K componentes Gaussianos. Cada componente Gaussiano k tem um vetor médio (μ_k), matriz de covariância (Σ_k) e um peso de mistura (π_k) que representa quão prevalente é aquele cluster. Ao contrário do K-Means, que faz atribuições "duras", o GMM dá a cada ponto uma probabilidade de pertencer a cada cluster.

O ajuste do GMM é tipicamente feito via o algoritmo de Expectativa-Maximização (EM):

- **Inicialização**: Comece com palpites iniciais para as médias, covariâncias e coeficientes de mistura (ou use os resultados do K-Means como ponto de partida).

- **E-pass (Expectativa)**: Dado os parâmetros atuais, calcule a responsabilidade de cada cluster para cada ponto: essencialmente `r_nk = P(z_k | x_n)` onde z_k é a variável latente indicando a pertença ao cluster para o ponto x_n. Isso é feito usando o teorema de Bayes, onde calculamos a probabilidade posterior de cada ponto pertencer a cada cluster com base nos parâmetros atuais. As responsabilidades são calculadas como:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
onde:
- \( \pi_k \) é o coeficiente de mistura para o cluster k (probabilidade a priori do cluster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) é a função de densidade de probabilidade Gaussiana para o ponto \( x_n \) dado a média \( \mu_k \) e a covariância \( \Sigma_k \).

- **M-pass (Maximização)**: Atualize os parâmetros usando as responsabilidades calculadas na E-pass:
- Atualize cada média μ_k como a média ponderada dos pontos, onde os pesos são as responsabilidades.
- Atualize cada covariância Σ_k como a covariância ponderada dos pontos atribuídos ao cluster k.
- Atualize os coeficientes de mistura π_k como a responsabilidade média para o cluster k.

- **Iterar** os passos E e M até a convergência (os parâmetros se estabilizam ou a melhoria da verossimilhança está abaixo de um limite).

O resultado é um conjunto de distribuições Gaussianas que modelam coletivamente a distribuição geral dos dados. Podemos usar o GMM ajustado para agrupar, atribuindo cada ponto à Gaussiana com a maior probabilidade, ou manter as probabilidades para incerteza. Também é possível avaliar a verossimilhança de novos pontos para ver se eles se encaixam no modelo (útil para detecção de anomalias).

> [!TIP]
> *Casos de uso em cibersegurança:* O GMM pode ser usado para detecção de anomalias modelando a distribuição de dados normais: qualquer ponto com probabilidade muito baixa sob a mistura aprendida é sinalizado como anomalia. Por exemplo, você poderia treinar um GMM em características de tráfego de rede legítimo; uma conexão de ataque que não se assemelha a nenhum cluster aprendido teria uma baixa probabilidade. Os GMMs também são usados para agrupar atividades onde os clusters podem ter formas diferentes – por exemplo, agrupando usuários por perfis de comportamento, onde as características de cada perfil podem ser semelhantes a Gaussianas, mas com sua própria estrutura de variância. Outro cenário: na detecção de phishing, características de e-mails legítimos podem formar um cluster Gaussiano, phishing conhecido outro, e novas campanhas de phishing podem aparecer como uma Gaussiana separada ou como pontos de baixa probabilidade em relação à mistura existente.

#### Suposições e Limitações

O GMM é uma generalização do K-Means que incorpora covariância, de modo que os clusters podem ser elipsoidais (não apenas esféricos). Ele lida com clusters de diferentes tamanhos e formas se a covariância for completa. O clustering suave é uma vantagem quando os limites dos clusters são difusos – por exemplo, em cibersegurança, um evento pode ter características de vários tipos de ataque; o GMM pode refletir essa incerteza com probabilidades. O GMM também fornece uma estimativa de densidade probabilística dos dados, útil para detectar outliers (pontos com baixa probabilidade sob todos os componentes da mistura).

Por outro lado, o GMM requer especificar o número de componentes K (embora se possa usar critérios como BIC/AIC para selecioná-lo). O EM pode às vezes convergir lentamente ou para um ótimo local, então a inicialização é importante (geralmente executa-se o EM várias vezes). Se os dados não seguirem realmente uma mistura de Gaussianas, o modelo pode ser um ajuste ruim. Também há o risco de uma Gaussiana encolher para cobrir apenas um outlier (embora a regularização ou limites mínimos de covariância possam mitigar isso).

<details>
<summary>Exemplo --  Clustering Suave & Pontuações de Anomalia
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
Neste código, treinamos um GMM com 3 Gaussianos no tráfego normal (assumindo que conhecemos 3 perfis de tráfego legítimo). As médias e covariâncias impressas descrevem esses clusters (por exemplo, uma média pode estar em torno de [50,500] correspondendo ao centro de um cluster, etc.). Em seguida, testamos uma conexão suspeita [duration=200, bytes=800]. O predict_proba fornece a probabilidade deste ponto pertencer a cada um dos 3 clusters – esperaríamos que essas probabilidades fossem muito baixas ou altamente distorcidas, uma vez que [200,800] está longe dos clusters normais. A pontuação geral score_samples (log-verossimilhança) é impressa; um valor muito baixo indica que o ponto não se encaixa bem no modelo, sinalizando-o como uma anomalia. Na prática, pode-se definir um limite na log-verossimilhança (ou na probabilidade máxima) para decidir se um ponto é suficientemente improvável para ser considerado malicioso. O GMM, portanto, fornece uma maneira fundamentada de fazer detecção de anomalias e também gera clusters suaves que reconhecem a incerteza.

### Isolation Forest

**Isolation Forest** é um algoritmo de detecção de anomalias em conjunto baseado na ideia de isolar pontos aleatoriamente. O princípio é que anomalias são poucas e diferentes, portanto, são mais fáceis de isolar do que pontos normais. Uma Isolation Forest constrói muitas árvores de isolamento binárias (árvores de decisão aleatórias) que particionam os dados aleatoriamente. Em cada nó de uma árvore, uma característica aleatória é selecionada e um valor de divisão aleatório é escolhido entre o mínimo e o máximo dessa característica para os dados naquele nó. Essa divisão divide os dados em duas ramificações. A árvore é crescida até que cada ponto esteja isolado em sua própria folha ou uma altura máxima da árvore seja alcançada.

A detecção de anomalias é realizada observando o comprimento do caminho de cada ponto nessas árvores aleatórias – o número de divisões necessárias para isolar o ponto. Intuitivamente, anomalias (outliers) tendem a ser isoladas mais rapidamente porque uma divisão aleatória é mais provável de separar um outlier (que está em uma região esparsa) do que um ponto normal em um cluster denso. A Isolation Forest calcula uma pontuação de anomalia a partir do comprimento médio do caminho em todas as árvores: caminho médio mais curto → mais anômalo. As pontuações geralmente são normalizadas para [0,1], onde 1 significa anomalia muito provável.

> [!TIP]
> *Casos de uso em cibersegurança:* Isolation Forests têm sido usados com sucesso em detecção de intrusões e detecção de fraudes. Por exemplo, treine uma Isolation Forest em logs de tráfego de rede que contêm principalmente comportamento normal; a floresta produzirá caminhos curtos para tráfego estranho (como um IP que usa uma porta desconhecida ou um padrão de tamanho de pacote incomum), sinalizando-o para inspeção. Como não requer ataques rotulados, é adequado para detectar tipos de ataque desconhecidos. Também pode ser implantado em dados de login de usuários para detectar tomadas de conta (os horários ou locais de login anômalos são isolados rapidamente). Em um caso de uso, uma Isolation Forest pode proteger uma empresa monitorando métricas do sistema e gerando um alerta quando uma combinação de métricas (CPU, rede, alterações de arquivos) parece muito diferente (caminhos de isolamento curtos) dos padrões históricos.

#### Assumptions and Limitations

**Vantagens**: Isolation Forest não requer uma suposição de distribuição; ele visa diretamente o isolamento. É eficiente em dados de alta dimensão e grandes conjuntos de dados (complexidade linear $O(n\log n)$ para construir a floresta) uma vez que cada árvore isola pontos com apenas um subconjunto de características e divisões. Tende a lidar bem com características numéricas e pode ser mais rápido do que métodos baseados em distância que podem ser $O(n^2)$. Também fornece automaticamente uma pontuação de anomalia, então você pode definir um limite para alertas (ou usar um parâmetro de contaminação para decidir automaticamente um corte com base em uma fração de anomalia esperada).

**Limitações**: Devido à sua natureza aleatória, os resultados podem variar ligeiramente entre execuções (embora com um número suficiente de árvores isso seja menor). Se os dados tiverem muitas características irrelevantes ou se as anomalias não se diferenciarem fortemente em nenhuma característica, o isolamento pode não ser eficaz (divisões aleatórias poderiam isolar pontos normais por acaso – no entanto, a média de muitas árvores mitiga isso). Além disso, a Isolation Forest geralmente assume que as anomalias são uma pequena minoria (o que geralmente é verdade em cenários de cibersegurança).

<details>
<summary>Exemplo -- Detectando Outliers em Logs de Rede
</summary>

Usaremos o conjunto de dados de teste anterior (que contém pontos normais e alguns pontos de ataque) e executaremos uma Isolation Forest para ver se ela pode separar os ataques. Assumiremos que esperamos ~15% dos dados como anômalos (para demonstração).
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
Neste código, instanciamos `IsolationForest` com 100 árvores e definimos `contamination=0.15` (o que significa que esperamos cerca de 15% de anomalias; o modelo definirá seu limite de pontuação para que ~15% dos pontos sejam sinalizados). Ajustamos em `X_test_if`, que contém uma mistura de pontos normais e de ataque (nota: normalmente você ajustaria em dados de treinamento e depois usaria predict em novos dados, mas aqui, para ilustração, ajustamos e prevemos no mesmo conjunto para observar diretamente os resultados).

A saída mostra os rótulos previstos para os primeiros 20 pontos (onde -1 indica anomalia). Também imprimimos quantas anomalias foram detectadas no total e alguns exemplos de pontuações de anomalia. Esperaríamos que aproximadamente 18 dos 120 pontos fossem rotulados como -1 (já que a contaminação era de 15%). Se nossas 20 amostras de ataque são realmente as mais discrepantes, a maioria delas deve aparecer nessas previsões -1. A pontuação de anomalia (a função de decisão do Isolation Forest) é maior para pontos normais e menor (mais negativa) para anomalias – imprimimos alguns valores para ver a separação. Na prática, pode-se classificar os dados por pontuação para ver os principais outliers e investigá-los. O Isolation Forest, portanto, fornece uma maneira eficiente de filtrar grandes dados de segurança não rotulados e selecionar as instâncias mais irregulares para análise humana ou escrutínio automatizado adicional.

### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** é uma técnica de redução de dimensionalidade não linear projetada especificamente para visualizar dados de alta dimensão em 2 ou 3 dimensões. Ela converte similaridades entre pontos de dados em distribuições de probabilidade conjunta e tenta preservar a estrutura dos bairros locais na projeção de menor dimensão. Em termos mais simples, o t-SNE coloca pontos em (digamos) 2D de forma que pontos similares (no espaço original) fiquem próximos e pontos dissimilares fiquem distantes com alta probabilidade.

O algoritmo tem duas etapas principais:

1. **Calcular afinidades par a par no espaço de alta dimensão:** Para cada par de pontos, o t-SNE calcula uma probabilidade de que um escolheria aquele par como vizinhos (isso é feito centralizando uma distribuição Gaussiana em cada ponto e medindo distâncias – o parâmetro de perplexidade influencia o número efetivo de vizinhos considerados).
2. **Calcular afinidades par a par no espaço de baixa dimensão (por exemplo, 2D):** Inicialmente, os pontos são colocados aleatoriamente em 2D. O t-SNE define uma probabilidade similar para distâncias neste mapa (usando um núcleo de distribuição t de Student, que tem caudas mais pesadas do que a Gaussiana para permitir que pontos distantes tenham mais liberdade).
3. **Descida do Gradiente:** O t-SNE então move iterativamente os pontos em 2D para minimizar a divergência de Kullback–Leibler (KL) entre a distribuição de afinidade de alta dimensão e a de baixa dimensão. Isso faz com que o arranjo em 2D reflita a estrutura de alta dimensão o máximo possível – pontos que estavam próximos no espaço original se atrairão, e aqueles distantes se repelirão, até que um equilíbrio seja encontrado.

O resultado é frequentemente um gráfico de dispersão visualmente significativo onde os clusters nos dados se tornam aparentes.

> [!TIP]
> *Casos de uso em cibersegurança:* o t-SNE é frequentemente usado para **visualizar dados de segurança de alta dimensão para análise humana**. Por exemplo, em um centro de operações de segurança, analistas poderiam pegar um conjunto de dados de eventos com dezenas de características (números de porta, frequências, contagens de bytes, etc.) e usar o t-SNE para produzir um gráfico 2D. Ataques podem formar seus próprios clusters ou se separar dos dados normais neste gráfico, tornando-os mais fáceis de identificar. Foi aplicado a conjuntos de dados de malware para ver agrupamentos de famílias de malware ou a dados de intrusão de rede onde diferentes tipos de ataque se agrupam de forma distinta, orientando investigações adicionais. Essencialmente, o t-SNE fornece uma maneira de ver a estrutura em dados cibernéticos que, de outra forma, seriam incompreensíveis.

#### Suposições e Limitações

O t-SNE é ótimo para descoberta visual de padrões. Ele pode revelar clusters, subclusters e outliers que outros métodos lineares (como PCA) podem não conseguir. Tem sido usado em pesquisas de cibersegurança para visualizar dados complexos, como perfis de comportamento de malware ou padrões de tráfego de rede. Como preserva a estrutura local, é bom para mostrar agrupamentos naturais.

No entanto, o t-SNE é computacionalmente mais pesado (aproximadamente $O(n^2)$), então pode exigir amostragem para conjuntos de dados muito grandes. Também possui hiperparâmetros (perplexidade, taxa de aprendizado, iterações) que podem afetar a saída – por exemplo, diferentes valores de perplexidade podem revelar clusters em diferentes escalas. Gráficos de t-SNE podem às vezes ser mal interpretados – distâncias no mapa não são diretamente significativas globalmente (foca no bairro local, às vezes clusters podem parecer artificialmente bem separados). Além disso, o t-SNE é principalmente para visualização; não fornece uma maneira direta de projetar novos pontos de dados sem recomputação, e não é destinado a ser usado como pré-processamento para modelagem preditiva (UMAP é uma alternativa que aborda algumas dessas questões com velocidade mais rápida).

<details>
<summary>Exemplo -- Visualizando Conexões de Rede
</summary>

Usaremos o t-SNE para reduzir um conjunto de dados multifuncional para 2D. Para ilustração, vamos pegar os dados 4D anteriores (que tinham 3 clusters naturais de tráfego normal) e adicionar alguns pontos de anomalia. Em seguida, executamos o t-SNE e (conceitualmente) visualizamos os resultados.
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
Aqui combinamos nosso conjunto de dados normal 4D anterior com um punhado de outliers extremos (os outliers têm uma característica (“duração”) definida muito alta, etc., para simular um padrão estranho). Executamos t-SNE com uma perplexidade típica de 30. Os dados de saída data_2d têm a forma (1505, 2). Na verdade, não vamos plotar neste texto, mas se o fizéssemos, esperaríamos ver talvez três clusters compactos correspondendo aos 3 clusters normais, e os 5 outliers aparecendo como pontos isolados longe desses clusters. Em um fluxo de trabalho interativo, poderíamos colorir os pontos de acordo com seu rótulo (normal ou qual cluster, vs anomalia) para verificar essa estrutura. Mesmo sem rótulos, um analista pode notar aqueles 5 pontos sentados em espaço vazio no gráfico 2D e sinalizá-los. Isso mostra como t-SNE pode ser uma ferramenta poderosa para a detecção visual de anomalias e inspeção de clusters em dados de cibersegurança, complementando os algoritmos automatizados acima.

</details>


{{#include ../banners/hacktricks-training.md}}
