# Algoritmos de Aprendizado Não Supervisionado

{{#include ../banners/hacktricks-training.md}}

## Aprendizado Não Supervisionado

O aprendizado não supervisionado é um tipo de machine learning no qual o modelo é treinado com dados sem respostas rotuladas. O objetivo é encontrar padrões, estruturas ou relações nos dados. Diferentemente do aprendizado supervisionado, no qual o modelo aprende a partir de exemplos rotulados, os algoritmos de aprendizado não supervisionado trabalham com dados não rotulados.
O aprendizado não supervisionado é frequentemente usado em tarefas como clustering, redução de dimensionalidade e detecção de anomalias. Ele pode ajudar a descobrir padrões ocultos nos dados, agrupar itens semelhantes ou reduzir a complexidade dos dados preservando suas características essenciais.


### Clustering K-Means

K-Means é um algoritmo de clustering baseado em centróides que particiona os dados em K clusters, atribuindo cada ponto à média de cluster mais próxima. O algoritmo funciona da seguinte forma:
1. **Inicialização**: Escolha K centros de cluster iniciais (centróides), geralmente de forma aleatória ou usando métodos mais inteligentes, como k-means++
2. **Atribuição**: Atribua cada ponto de dados ao centróide mais próximo com base em uma métrica de distância (por exemplo, distância euclidiana).
3. **Atualização**: Recalcule os centróides obtendo a média de todos os pontos de dados atribuídos a cada cluster.
4. **Repetição**: Repita as etapas 2–3 até que as atribuições dos clusters se estabilizem (os centróides não se movam mais significativamente).

> [!TIP]
> *Casos de uso em cybersecurity:* K-Means é usado para detecção de intrusões por meio do clustering de eventos de rede. Por exemplo, pesquisadores aplicaram K-Means ao dataset de intrusões KDD Cup 99 e descobriram que ele particionava efetivamente o tráfego em clusters de tráfego normal e de ataques. Na prática, analistas de segurança podem fazer clustering de entradas de log ou de dados de comportamento de usuários para encontrar grupos de atividades semelhantes; quaisquer pontos que não pertençam a um cluster bem definido podem indicar anomalias (por exemplo, uma nova variante de malware formando seu próprio cluster pequeno). K-Means também pode ajudar na classificação de famílias de malware ao agrupar binários com base em perfis de comportamento ou vetores de características.

#### Seleção de K
O número de clusters (K) é um hiperparâmetro que precisa ser definido antes de executar o algoritmo. Técnicas como o Método do Cotovelo ou o Silhouette Score podem ajudar a determinar um valor adequado para K, avaliando o desempenho do clustering:

- **Método do Cotovelo**: Plote a soma das distâncias quadráticas de cada ponto até o centróide do cluster ao qual foi atribuído como uma função de K. Procure um ponto de “cotovelo” em que a taxa de redução mude bruscamente, indicando um número adequado de clusters.
- **Silhouette Score**: Calcule o silhouette score para diferentes valores de K. Um silhouette score mais alto indica clusters mais bem definidos.

#### Premissas e Limitações

K-Means pressupõe que os **clusters são esféricos e têm o mesmo tamanho**, o que pode não ser verdadeiro para todos os datasets. Ele é sensível à posição inicial dos centróides e pode convergir para mínimos locais. Além disso, K-Means não é adequado para datasets com densidades variadas, formatos não globulares ou features com escalas diferentes. Etapas de pré-processamento, como normalização ou padronização, podem ser necessárias para garantir que todas as features contribuam igualmente para os cálculos de distância.

<details>
<summary>Exemplo -- Clustering de Eventos de Rede
</summary>
Abaixo, simulamos dados de tráfego de rede e usamos K-Means para fazer clustering. Suponha que tenhamos eventos com features como duração da conexão e quantidade de bytes. Criamos 3 clusters de tráfego “normal” e 1 cluster pequeno representando um padrão de ataque. Em seguida, executamos K-Means para verificar se ele os separa.
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
Neste exemplo, o K-Means deve encontrar 4 clusters. O pequeno cluster de ataque (com duração excepcionalmente alta, ~200) idealmente formará seu próprio cluster, dada sua distância dos clusters normais. Imprimimos os tamanhos e os centros dos clusters para interpretar os resultados. Em um cenário real, seria possível classificar o cluster com poucos pontos como possíveis anomalias ou inspecionar seus membros em busca de atividade maliciosa.
</details>

### Clustering Hierárquico

O clustering hierárquico cria uma hierarquia de clusters usando uma abordagem de baixo para cima (aglomerativa) ou de cima para baixo (divisiva):

1. **Aglomerativa (Bottom-Up)**: Começa com cada ponto de dados como um cluster separado e, iterativamente, mescla os clusters mais próximos até que reste um único cluster ou que um critério de parada seja atingido.
2. **Divisiva (Top-Down)**: Começa com todos os pontos de dados em um único cluster e, iterativamente, divide os clusters até que cada ponto de dados seja seu próprio cluster ou que um critério de parada seja atingido.

O clustering aglomerativo requer uma definição da distância entre clusters e um critério de linkage para decidir quais clusters mesclar. Os métodos de linkage comuns incluem single linkage (distância entre os pontos mais próximos de dois clusters), complete linkage (distância entre os pontos mais distantes), average linkage etc., e a métrica de distância geralmente é a Euclidiana. A escolha do linkage afeta o formato dos clusters produzidos. Não é necessário especificar previamente o número de clusters K; é possível “cortar” o dendrograma em um nível escolhido para obter o número desejado de clusters.

O clustering hierárquico produz um dendrograma, uma estrutura semelhante a uma árvore que mostra as relações entre os clusters em diferentes níveis de granularidade. O dendrograma pode ser cortado em um nível desejado para obter um número específico de clusters.

> [!TIP]
> *Casos de uso em cybersecurity:* O clustering hierárquico pode organizar eventos ou entidades em uma árvore para identificar relações. Por exemplo, na análise de malware, o clustering aglomerativo poderia agrupar amostras por similaridade comportamental, revelando uma hierarquia de famílias e variantes de malware. Em network security, seria possível agrupar fluxos de tráfego IP e usar o dendrograma para visualizar subdivisões do tráfego (por exemplo, primeiro por protocolo e depois por comportamento). Como não é necessário escolher K antecipadamente, essa técnica é útil ao explorar dados novos cujo número de categorias de ataque é desconhecido.

#### Assumptions and Limitations

O clustering hierárquico não assume um formato específico de cluster e pode capturar clusters aninhados. Ele é útil para descobrir taxonomias ou relações entre grupos (por exemplo, agrupar malware por subgrupos de famílias). É determinístico (não há problemas de inicialização aleatória). Uma vantagem importante é o dendrograma, que fornece informações sobre a estrutura de clustering dos dados em todas as escalas – os analistas de segurança podem decidir um ponto de corte apropriado para identificar clusters relevantes. No entanto, ele é computacionalmente caro (normalmente $O(n^2)$ ou pior em termos de tempo para implementações ingênuas) e não é viável para datasets muito grandes. Também é um procedimento guloso – depois que uma mesclagem ou divisão é realizada, ela não pode ser desfeita, o que pode levar a clusters subótimos caso ocorra um erro no início. Outliers também podem afetar algumas estratégias de linkage (o single-link pode causar o efeito de “encadeamento”, no qual os clusters se conectam por meio de outliers).

<details>
<summary>Exemplo -- Clustering Aglomerativo de Eventos
</summary>

Vamos reutilizar os dados sintéticos do exemplo de K-Means (3 clusters normais + 1 cluster de ataque) e aplicar o clustering aglomerativo. Em seguida, ilustramos como obter um dendrograma e os rótulos dos clusters.
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

### DBSCAN (Density-Based Spatial Clustering of Applications with Noise)

DBSCAN é um algoritmo de clustering baseado em densidade que agrupa pontos próximos entre si, enquanto marca pontos em regiões de baixa densidade como outliers. Ele é particularmente útil para datasets com densidades variadas e formatos não esféricos.

O DBSCAN funciona definindo dois parâmetros:
- **Epsilon (ε)**: A distância máxima entre dois pontos para que sejam considerados parte do mesmo cluster.
- **MinPts**: O número mínimo de pontos necessário para formar uma região densa (core point).

O DBSCAN identifica core points, border points e noise points:
- **Core Point**: Um ponto com pelo menos MinPts vizinhos dentro da distância ε.
- **Border Point**: Um ponto que está dentro da distância ε de um core point, mas tem menos de MinPts vizinhos.
- **Noise Point**: Um ponto que não é um core point nem um border point.

O clustering prossegue selecionando um core point não visitado, marcando-o como um novo cluster e, em seguida, adicionando recursivamente todos os pontos density-reachable a partir dele (core points e seus vizinhos etc.). Border points são adicionados ao cluster de um core próximo. Depois de expandir todos os pontos alcançáveis, o DBSCAN passa para outro core não visitado para iniciar um novo cluster. Os pontos não alcançados por nenhum core permanecem marcados como noise.

> [!TIP]
> *Casos de uso em cybersecurity:* O DBSCAN é útil para detecção de anomalias no tráfego de rede. Por exemplo, a atividade normal dos usuários pode formar um ou mais clusters densos no espaço de características, enquanto comportamentos de ataque inéditos aparecem como pontos dispersos que o DBSCAN marcará como noise (outliers). Ele tem sido usado para agrupar registros de fluxos de rede, nos quais pode detectar port scans ou tráfego de denial-of-service como regiões esparsas de pontos. Outra aplicação é o agrupamento de variantes de malware: se a maioria das amostras formar clusters por família, mas algumas não se encaixarem em nenhum lugar, essas poucas podem ser malwares zero-day. A capacidade de sinalizar noise permite que as equipes de segurança se concentrem na investigação desses outliers.

#### Assumptions and Limitations

**Assumptions & Strengths:**: O DBSCAN não assume clusters esféricos – ele pode encontrar clusters com formatos arbitrários (inclusive clusters em cadeia ou adjacentes). Ele determina automaticamente o número de clusters com base na densidade dos dados e consegue identificar outliers como noise. Isso o torna poderoso para dados do mundo real com formatos irregulares e noise. Ele é robusto a outliers (ao contrário do K-Means, que os força a entrar em clusters). Ele funciona bem quando os clusters têm densidade aproximadamente uniforme.

**Limitations**: O desempenho do DBSCAN depende da escolha de valores apropriados para ε e MinPts. Ele pode ter dificuldades com dados que apresentam densidades variadas – um único ε não consegue acomodar clusters densos e esparsos ao mesmo tempo. Se ε for pequeno demais, ele classificará a maioria dos pontos como noise; se for grande demais, os clusters poderão ser mesclados incorretamente. Além disso, o DBSCAN pode ser ineficiente em datasets muito grandes (ingenuamente $O(n^2)$, embora a indexação espacial possa ajudar). Em espaços de características de alta dimensionalidade, o conceito de “distância dentro de ε” pode se tornar menos significativo (a maldição da dimensionalidade), e o DBSCAN pode exigir um ajuste cuidadoso dos parâmetros ou não conseguir encontrar clusters intuitivos. Apesar disso, extensões como HDBSCAN resolvem alguns problemas (como densidade variável).

<details>
<summary>Example -- Clustering with Noise
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
Neste trecho, ajustamos `eps` e `min_samples` para se adequar à escala dos nossos dados (15.0 em unidades de características e exigindo 5 pontos para formar um cluster). O DBSCAN deve encontrar 2 clusters (os clusters de tráfego normal) e sinalizar os 5 outliers inseridos como ruído. Exibimos o número de clusters em relação aos pontos de ruído para verificar isso. Em um cenário real, seria possível iterar sobre ε (usando uma heurística de gráfico de k-distância para escolher ε) e MinPts (geralmente definido como aproximadamente a dimensionalidade dos dados + 1, como regra prática) para encontrar resultados de clustering estáveis. A capacidade de rotular explicitamente o ruído ajuda a separar possíveis dados de ataque para análise posterior.

</details>

### Principal Component Analysis (PCA)

PCA é uma técnica de **redução de dimensionalidade** que encontra um novo conjunto de eixos ortogonais (componentes principais) que capturam a variância máxima nos dados. Em termos simples, PCA gira e projeta os dados em um novo sistema de coordenadas, de modo que o primeiro componente principal (PC1) explique a maior variância possível, o segundo componente (PC2) explique a maior variância ortogonal ao PC1, e assim por diante. Matematicamente, PCA calcula os autovetores da matriz de covariância dos dados – esses autovetores são as direções dos componentes principais, e os autovalores correspondentes indicam a quantidade de variância explicada por cada um. Ele é frequentemente usado para extração de características, visualização e redução de ruído.

Observe que isso é útil se as dimensões do dataset contiverem **dependências lineares ou correlações significativas**.

PCA funciona identificando os componentes principais dos dados, que são as direções de variância máxima. As etapas envolvidas no PCA são:
1. **Padronização**: Centralizar os dados subtraindo a média e escalá-los para obter variância unitária.
2. **Matriz de Covariância**: Calcular a matriz de covariância dos dados padronizados para compreender as relações entre as características.
3. **Decomposição em Autovalores**: Realizar a decomposição em autovalores da matriz de covariância para obter os autovalores e autovetores.
4. **Selecionar Componentes Principais**: Ordenar os autovalores em ordem decrescente e selecionar os K principais autovetores correspondentes aos maiores autovalores. Esses autovetores formam o novo espaço de características.
5. **Transformar os Dados**: Projetar os dados originais no novo espaço de características usando os componentes principais selecionados.
PCA é amplamente usado para visualização de dados, redução de ruído e como etapa de pré-processamento para outros algoritmos de machine learning. Ele ajuda a reduzir a dimensionalidade dos dados enquanto preserva sua estrutura essencial.

#### Autovalores e Autovetores

Um autovalor é um escalar que indica a quantidade de variância capturada pelo autovetor correspondente. Um autovetor representa uma direção no espaço de características ao longo da qual os dados variam mais.

Imagine que A seja uma matriz quadrada e v seja um vetor não nulo tal que: `A * v = λ * v`
onde:
- A é uma matriz quadrada como [ [1, 2], [2, 1]] (por exemplo, uma matriz de covariância)
- v é um autovetor (por exemplo, [1, 1])

Então, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, que será o autovalor λ multiplicado pelo autovetor v, fazendo com que o autovalor λ = 3.

#### Autovalores e Autovetores em PCA

Vamos explicar isso com um exemplo. Imagine que você tenha um dataset com muitas imagens em escala de cinza de rostos com 100x100 pixels. Cada pixel pode ser considerado uma característica, portanto você tem 10.000 características por imagem (ou um vetor de 10000 componentes por imagem). Se quiser reduzir a dimensionalidade desse dataset usando PCA, você seguiria estas etapas:

1. **Padronização**: Centralizar os dados subtraindo do dataset a média de cada característica (pixel).
2. **Matriz de Covariância**: Calcular a matriz de covariância dos dados padronizados, que captura como as características (pixels) variam em conjunto.
- Observe que a covariância entre duas variáveis (pixels, neste caso) indica o quanto elas mudam juntas; portanto, a ideia aqui é descobrir quais pixels tendem a aumentar ou diminuir juntos em uma relação linear.
- Por exemplo, se o pixel 1 e o pixel 2 tendem a aumentar juntos, a covariância entre eles será positiva.
- A matriz de covariância será uma matriz de 10.000x10.000, na qual cada entrada representa a covariância entre dois pixels.
3. **Resolver a equação de autovalores**: A equação de autovalores a ser resolvida é `C * v = λ * v`, onde C é a matriz de covariância, v é o autovetor e λ é o autovalor. Ela pode ser resolvida usando métodos como:
- **Decomposição em Autovalores**: Realizar a decomposição em autovalores da matriz de covariância para obter os autovalores e autovetores.
- **Decomposição em Valores Singulares (SVD)**: Como alternativa, você pode usar SVD para decompor a matriz de dados em valores e vetores singulares, o que também pode produzir os componentes principais.
4. **Selecionar Componentes Principais**: Ordenar os autovalores em ordem decrescente e selecionar os K principais autovetores correspondentes aos maiores autovalores. Esses autovetores representam as direções de variância máxima nos dados.

> [!TIP]
> *Casos de uso em cybersecurity:* Um uso comum de PCA em segurança é a redução de características para detecção de anomalias. Por exemplo, um sistema de detecção de intrusão com mais de 40 métricas de rede (como as características do NSL-KDD) pode usar PCA para reduzir os dados a alguns componentes, resumindo-os para visualização ou fornecimento a algoritmos de clustering. Os analistas podem plotar o tráfego de rede no espaço dos dois primeiros componentes principais para verificar se os ataques se separam do tráfego normal. PCA também pode ajudar a eliminar características redundantes (como bytes enviados e bytes recebidos, caso estejam correlacionados), tornando os algoritmos de detecção mais robustos e rápidos.

#### Suposições e Limitações

PCA pressupõe que os **eixos principais da variância sejam significativos** – ele é um método linear, portanto captura correlações lineares nos dados. Ele não é supervisionado, pois usa apenas a covariância das características. As vantagens do PCA incluem redução de ruído (componentes de baixa variância frequentemente correspondem a ruído) e descorrelação das características. Ele é computacionalmente eficiente para dimensões moderadamente altas e frequentemente é uma etapa de pré-processamento útil para outros algoritmos (para mitigar a maldição da dimensionalidade). Uma limitação é que PCA se restringe a relações lineares – ele não captura estruturas não lineares complexas (enquanto autoencoders ou t-SNE podem capturá-las). Além disso, os componentes do PCA podem ser difíceis de interpretar em termos das características originais (eles são combinações das características originais). Em cybersecurity, é necessário ter cautela: um ataque que cause apenas uma alteração sutil em uma característica de baixa variância pode não aparecer nos principais PCs (já que PCA prioriza a variância, não necessariamente o que é “interessante”).

<details>
<summary>Exemplo -- Reduzindo as Dimensões de Dados de Rede
</summary>

Suponha que tenhamos logs de conexões de rede com várias características (por exemplo, durações, bytes, contagens). Vamos gerar um dataset sintético de 4 dimensões (com alguma correlação entre as características) e usar PCA para reduzi-lo a 2 dimensões para visualização ou análise posterior.
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
Aqui, usamos os clusters de tráfego normal anteriores e estendemos cada ponto de dados com dois recursos adicionais (packets e errors) que apresentam correlação com bytes e duration. O PCA é então usado para compactar os 4 recursos em 2 componentes principais. Imprimimos a explained variance ratio, que pode mostrar que, por exemplo, >95% da variância é capturada pelos 2 componentes (o que significa pouca perda de informação). A saída também mostra a redução do formato dos dados de (1500, 4) para (1500, 2). Os primeiros pontos no espaço PCA são apresentados como exemplo. Na prática, seria possível plotar data_2d para verificar visualmente se os clusters são distinguíveis. Se houvesse uma anomalia, ela poderia aparecer como um ponto distante do cluster principal no espaço PCA. Assim, o PCA ajuda a condensar dados complexos em um formato gerenciável para interpretação humana ou como entrada para outros algoritmos.

</details>


### Gaussian Mixture Models (GMM)

Um Gaussian Mixture Model presume que os dados são gerados a partir de uma mistura de **várias distribuições Gaussianas (normais) com parâmetros desconhecidos**. Em essência, trata-se de um modelo probabilístico de clustering: ele tenta atribuir suavemente cada ponto a um dos K componentes Gaussianos. Cada componente Gaussiano k possui um vetor de média (μ_k), uma matriz de covariância (Σ_k) e um peso de mistura (π_k), que representa a prevalência desse cluster. Diferentemente do K-Means, que realiza atribuições “hard”, o GMM fornece a cada ponto uma probabilidade de pertencer a cada cluster.

O ajuste do GMM normalmente é feito por meio do algoritmo Expectation-Maximization (EM):

- **Initialization**: Começa com estimativas iniciais para as médias, covariâncias e coeficientes de mistura (ou usa os resultados do K-Means como ponto de partida).

- **E-step (Expectation)**: Dado o conjunto atual de parâmetros, calcula a responsabilidade de cada cluster por cada ponto: essencialmente `r_nk = P(z_k | x_n)`, onde z_k é a variável latente que indica a associação ao cluster do ponto x_n. Isso é feito usando o teorema de Bayes, calculando a probabilidade posterior de cada ponto pertencer a cada cluster com base nos parâmetros atuais. As responsabilidades são calculadas como:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
onde:
- \( \pi_k \) é o coeficiente de mistura do cluster k (probabilidade anterior do cluster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) é a função de densidade de probabilidade Gaussiana para o ponto \( x_n \), dada a média \( \mu_k \) e a covariância \( \Sigma_k \).

- **M-step (Maximization)**: Atualiza os parâmetros usando as responsabilidades calculadas no E-step:
- Atualiza cada média μ_k como a média ponderada dos pontos, em que os pesos são as responsabilidades.
- Atualiza cada covariância Σ_k como a covariância ponderada dos pontos atribuídos ao cluster k.
- Atualiza os coeficientes de mistura π_k como a responsabilidade média pelo cluster k.

- **Iterate** os passos E e M até a convergência (quando os parâmetros se estabilizam ou a melhoria da likelihood fica abaixo de um limite).

O resultado é um conjunto de distribuições Gaussianas que, coletivamente, modelam a distribuição geral dos dados. Podemos usar o GMM ajustado para fazer clustering, atribuindo cada ponto à Gaussiana com a maior probabilidade, ou manter as probabilidades para representar a incerteza. Também é possível avaliar a likelihood de novos pontos para verificar se eles se ajustam ao modelo (o que é útil para detecção de anomalias).

> [!TIP]
> *Casos de uso em cybersecurity:* O GMM pode ser usado para detecção de anomalias ao modelar a distribuição de dados normais: qualquer ponto com probabilidade muito baixa sob a mistura aprendida é sinalizado como anomalia. Por exemplo, seria possível treinar um GMM com features de tráfego de rede legítimo; uma conexão de ataque que não se parecesse com nenhum cluster aprendido teria uma likelihood baixa. GMMs também são usados para agrupar atividades em que os clusters podem ter formatos diferentes – por exemplo, agrupando usuários por perfis comportamentais, nos quais as features de cada perfil podem ser semelhantes às Gaussianas, mas com sua própria estrutura de variância. Outro cenário ocorre na detecção de phishing: as features de emails legítimos podem formar um cluster Gaussiano, os emails de phishing conhecidos podem formar outro, e novas campanhas de phishing podem surgir como uma Gaussiana separada ou como pontos com likelihood baixa em relação à mistura existente.

#### Assumptions and Limitations

O GMM é uma generalização do K-Means que incorpora a covariância, permitindo que os clusters sejam elipsoidais (e não apenas esféricos). Ele lida com clusters de tamanhos e formatos diferentes quando a covariância é full. O clustering suave é uma vantagem quando os limites entre clusters são imprecisos – por exemplo, em cybersecurity, um evento pode apresentar características de vários tipos de ataque; o GMM pode representar essa incerteza com probabilidades. O GMM também fornece uma estimativa probabilística da densidade dos dados, útil para detectar outliers (pontos com likelihood baixa em todos os componentes da mistura).

Por outro lado, o GMM exige a especificação do número de componentes K (embora seja possível usar critérios como BIC/AIC para selecioná-lo). O EM às vezes pode convergir lentamente ou para um ótimo local, portanto a inicialização é importante (é comum executar o EM várias vezes). Se os dados não seguirem de fato uma mistura de Gaussianas, o modelo poderá não se ajustar bem. Também existe o risco de uma Gaussiana diminuir para abranger apenas um outlier (embora a regularização ou limites mínimos de covariância possam reduzir esse risco).


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
Neste código, treinamos um GMM com 3 Gaussianas no tráfego normal (supondo que conhecemos 3 perfis de tráfego legítimo). As médias e covariâncias exibidas descrevem esses clusters (por exemplo, uma média pode estar próxima de [50,500], correspondendo ao centro de um cluster, etc.). Em seguida, testamos uma conexão suspeita [duration=200, bytes=800]. O predict_proba fornece a probabilidade de esse ponto pertencer a cada um dos 3 clusters – esperaríamos que essas probabilidades fossem muito baixas ou altamente assimétricas, pois [200,800] está distante dos clusters normais. O score_samples geral (log-likelihood) é exibido; um valor muito baixo indica que o ponto não se ajusta bem ao modelo, sinalizando-o como uma anomalia. Na prática, seria possível definir um threshold no log-likelihood (ou na probabilidade máxima) para decidir se um ponto é improvável o suficiente para ser considerado malicioso. Assim, o GMM fornece uma maneira fundamentada de realizar anomaly detection e também produz clusters flexíveis que reconhecem a incerteza.
</details>

### Isolation Forest

**Isolation Forest** é um algoritmo de ensemble para anomaly detection baseado na ideia de isolar pontos aleatoriamente. O princípio é que as anomalias são poucas e diferentes, portanto são mais fáceis de isolar do que os pontos normais. Um Isolation Forest constrói muitas árvores binárias de isolamento (árvores de decisão aleatórias) que particionam os dados aleatoriamente. Em cada nó de uma árvore, uma feature aleatória é selecionada e um valor de divisão aleatório é escolhido entre o mínimo e o máximo dessa feature para os dados presentes naquele nó. Essa divisão separa os dados em dois ramos. A árvore cresce até que cada ponto seja isolado em sua própria folha ou que uma altura máxima da árvore seja atingida.

A anomaly detection é realizada observando o comprimento do caminho de cada ponto nessas árvores aleatórias – o número de divisões necessárias para isolar o ponto. Intuitivamente, as anomalias (outliers) tendem a ser isoladas mais rapidamente, pois uma divisão aleatória tem maior probabilidade de separar um outlier (que está em uma região esparsa) do que um ponto normal em um cluster denso. O Isolation Forest calcula um anomaly score a partir do comprimento médio do caminho em todas as árvores: caminho médio mais curto → mais anômalo. Os scores geralmente são normalizados para [0,1], em que 1 significa uma anomalia muito provável.

> [!TIP]
> *Casos de uso em cybersecurity:* Isolation Forests têm sido usados com sucesso em intrusion detection e fraud detection. Por exemplo, treine um Isolation Forest com logs de tráfego de rede contendo principalmente comportamento normal; o forest produzirá caminhos curtos para tráfego incomum (como um IP que usa uma porta nunca vista ou um padrão incomum de tamanho de pacotes), sinalizando-o para inspeção. Como não exige ataques rotulados, ele é adequado para detectar tipos desconhecidos de ataque. Também pode ser implantado em dados de login de usuários para detectar account takeovers (os horários ou locais anômalos de login são isolados rapidamente). Em um caso de uso, um Isolation Forest poderia proteger uma empresa monitorando métricas do sistema e gerando um alerta quando uma combinação de métricas (CPU, rede, alterações em arquivos) parecer muito diferente (caminhos de isolamento curtos) dos padrões históricos.

#### Assumptions and Limitations

**Vantagens**: O Isolation Forest não exige uma suposição de distribuição; ele visa diretamente o isolamento. É eficiente em dados de alta dimensionalidade e grandes datasets (complexidade linear $O(n\log n)$ para construir o forest), pois cada árvore isola pontos usando apenas um subconjunto de features e divisões. Ele tende a lidar bem com features numéricas e pode ser mais rápido que métodos baseados em distância, que podem ter complexidade $O(n^2)$. Também fornece automaticamente um anomaly score, permitindo definir um threshold para alertas (ou usar um parâmetro de contamination para decidir automaticamente um cutoff com base em uma fração esperada de anomalias).

**Limitações**: Devido à sua natureza aleatória, os resultados podem variar ligeiramente entre execuções (embora isso seja pouco significativo com um número suficiente de árvores). Se os dados tiverem muitas features irrelevantes ou se as anomalias não se diferenciarem significativamente em nenhuma feature, o isolamento pode não ser eficaz (divisões aleatórias podem isolar pontos normais por acaso – porém, a média de muitas árvores reduz esse efeito). Além disso, o Isolation Forest geralmente presume que as anomalias são uma pequena minoria (o que normalmente é verdade em cenários de cybersecurity).

<details>
<summary>Exemplo --  Detectando Outliers em Logs de Rede
</summary>

Usaremos o dataset de teste anterior (que contém pontos normais e alguns pontos de ataque) e executaremos um Isolation Forest para verificar se ele consegue separar os ataques. Supondremos que esperamos que aproximadamente 15% dos dados sejam anômalos (para fins de demonstração).
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
Neste código, instanciamos `IsolationForest` com 100 árvores e definimos `contamination=0.15` (o que significa que esperamos cerca de 15% de anomalias; o modelo definirá seu limiar de score de modo que aproximadamente 15% dos pontos sejam sinalizados). Nós o ajustamos em `X_test_if`, que contém uma mistura de pontos normais e de ataque (observação: normalmente, você ajustaria o modelo usando os dados de treinamento e depois usaria predict em novos dados, mas aqui, para fins de ilustração, ajustamos e fazemos a predição no mesmo conjunto para observar diretamente os resultados).

A saída mostra os rótulos previstos para os primeiros 20 pontos (onde -1 indica anomalia). Também exibimos quantas anomalias foram detectadas no total e alguns exemplos de scores de anomalia. Esperaríamos que aproximadamente 18 dos 120 pontos fossem rotulados como -1 (pois contamination foi definido como 15%). Se nossas 20 amostras de ataque forem realmente as mais discrepantes, a maioria delas deverá aparecer nessas predições -1. O score de anomalia (a função de decisão do Isolation Forest) é maior para pontos normais e menor (mais negativo) para anomalias — exibimos alguns valores para observar a separação. Na prática, seria possível ordenar os dados pelo score para visualizar os principais outliers e investigá-los. Dessa forma, o Isolation Forest oferece uma maneira eficiente de filtrar grandes volumes de dados de segurança não rotulados e identificar as instâncias mais irregulares para análise humana ou investigação automatizada adicional.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** é uma técnica não linear de redução de dimensionalidade projetada especificamente para visualizar dados de alta dimensionalidade em 2 ou 3 dimensões. Ela converte as similaridades entre os pontos de dados em distribuições de probabilidade conjuntas e tenta preservar a estrutura das vizinhanças locais na projeção de menor dimensionalidade. Em termos mais simples, o t-SNE posiciona os pontos (por exemplo) em 2D de modo que pontos semelhantes (no espaço original) terminem próximos uns dos outros e pontos diferentes terminem distantes, com alta probabilidade.

O algoritmo tem três etapas principais:

1. **Compute pairwise affinities in high-dimensional space:** Para cada par de pontos, o t-SNE calcula a probabilidade de que um deles escolha o outro como vizinho (isso é feito centralizando uma distribuição Gaussiana em cada ponto e medindo as distâncias — o parâmetro perplexity influencia o número efetivo de vizinhos considerados).
2. **Compute pairwise affinities in low-dimensional (e.g. 2D) space:** Inicialmente, os pontos são posicionados aleatoriamente em 2D. O t-SNE define uma probabilidade semelhante para as distâncias nesse mapa (usando um kernel de distribuição t de Student, que possui caudas mais pesadas que a distribuição Gaussiana, permitindo maior liberdade aos pontos distantes).
3. **Gradient Descent:** Em seguida, o t-SNE move iterativamente os pontos em 2D para minimizar a divergência de Kullback–Leibler (KL) entre a distribuição de afinidade de alta dimensionalidade e a de baixa dimensionalidade. Isso faz com que a disposição em 2D reflita ao máximo a estrutura de alta dimensionalidade — pontos que estavam próximos no espaço original atraem-se, enquanto os que estavam distantes repelem-se, até que um equilíbrio seja alcançado.

O resultado geralmente é um gráfico de dispersão visualmente significativo, no qual os clusters presentes nos dados se tornam aparentes.

> [!TIP]
> *Use cases in cybersecurity:* o t-SNE é frequentemente usado para **visualizar dados de segurança de alta dimensionalidade para análise humana**. Por exemplo, em um security operations center, os analistas poderiam coletar um dataset de eventos com dezenas de features (números de portas, frequências, contagens de bytes etc.) e usar o t-SNE para produzir um gráfico 2D. Os ataques poderiam formar seus próprios clusters ou se separar dos dados normais nesse gráfico, tornando-se mais fáceis de identificar. Ele tem sido aplicado a datasets de malware para observar agrupamentos de famílias de malware ou a dados de network intrusion, nos quais diferentes tipos de ataque formam clusters distintos, orientando investigações adicionais. Essencialmente, o t-SNE oferece uma maneira de visualizar estruturas em dados cibernéticos que, de outra forma, seriam difíceis de interpretar.

#### Assumptions and Limitations

O t-SNE é excelente para a descoberta visual de padrões. Ele pode revelar clusters, subclusters e outliers que outros métodos lineares (como PCA) talvez não revelem. Ele tem sido usado em pesquisas de cybersecurity para visualizar dados complexos, como perfis de comportamento de malware ou padrões de tráfego de rede. Como preserva a estrutura local, é eficaz para exibir agrupamentos naturais.

No entanto, o t-SNE é computacionalmente mais pesado (aproximadamente $O(n^2)$), portanto pode exigir amostragem para datasets muito grandes. Ele também possui hyperparameters (perplexity, learning rate, iterations) que podem afetar a saída — por exemplo, diferentes valores de perplexity podem revelar clusters em diferentes escalas. Os gráficos de t-SNE às vezes podem ser interpretados incorretamente — as distâncias no mapa não são diretamente significativas de forma global (ele se concentra na vizinhança local e, às vezes, os clusters podem parecer artificialmente bem separados). Além disso, o t-SNE é principalmente voltado à visualização; ele não oferece uma maneira simples de projetar novos pontos de dados sem recalcular o modelo e não foi projetado para ser usado como preprocessing em predictive modeling (UMAP é uma alternativa que resolve alguns desses problemas com maior velocidade).

<details>
<summary>Example -- Visualizing Network Connections
</summary>

Usaremos o t-SNE para reduzir um dataset com múltiplas features para 2D. Para fins de ilustração, vamos utilizar os dados 4D anteriores (que tinham 3 clusters naturais de tráfego normal) e adicionar alguns pontos de anomalia. Em seguida, executaremos o t-SNE e (conceitualmente) visualizaremos os resultados.
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
Aqui combinamos nosso dataset normal 4D anterior com um punhado de outliers extremos (os outliers têm um recurso (“duration”) definido como muito alto etc., para simular um padrão incomum). Executamos t-SNE com uma perplexidade típica de 30. Os dados de saída `data_2d` têm forma (1505, 2). Não faremos um plot neste texto, mas, se fizéssemos, esperaríamos ver talvez três clusters compactos correspondentes aos 3 clusters normais, e os 5 outliers aparecendo como pontos isolados distantes desses clusters. Em um workflow interativo, poderíamos colorir os pontos de acordo com seu rótulo (normal ou pertencente a qual cluster, contra anomaly) para verificar essa estrutura. Mesmo sem rótulos, um analista poderia notar esses 5 pontos em um espaço vazio no plot 2D e sinalizá-los. Isso mostra como t-SNE pode ser um recurso poderoso para auxiliar a detecção visual de anomalias e a inspeção de clusters em dados de cybersecurity, complementando os algoritmos automatizados acima.

</details>


### HDBSCAN (Clustering Espacial Hierárquico Baseado em Densidade de Aplicações com Ruído)

**HDBSCAN** é uma extensão do DBSCAN que elimina a necessidade de escolher um único valor global de `eps` e consegue recuperar clusters de **diferentes densidades**, construindo uma hierarquia de componentes conectados por densidade e, em seguida, condensando-a. Comparado ao DBSCAN vanilla, ele geralmente

* extrai clusters mais intuitivos quando alguns clusters são densos e outros são esparsos,
* possui apenas um hiperparâmetro real (`min_cluster_size`) e um valor padrão sensato,
* fornece a cada ponto uma *probabilidade* de pertencimento a um cluster e um **outlier score** (`outlier_scores_`), o que é extremamente útil para dashboards de threat-hunting.<sup>[[1]](#references)</sup>

> [!TIP]
> *Casos de uso em cybersecurity:* HDBSCAN é muito popular em pipelines modernos de threat-hunting - frequentemente você o verá em playbooks de hunting baseados em notebooks, distribuídos com suítes XDR comerciais. Uma receita prática é agrupar o tráfego de beaconing HTTP durante IR: user-agent, intervalo e comprimento da URI geralmente formam vários grupos compactos de atualizadores de software legítimos, enquanto beacons C2 permanecem como pequenos clusters de baixa densidade ou como puro ruído.

<details>
<summary>Exemplo - Encontrando canais C2 de beaconing</summary>
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

### Considerações de Robustez e Segurança – Poisoning e Adversarial Attacks (2023-2025)

Trabalhos recentes mostraram que **unsupervised learners *não* são imunes a atacantes ativos**:

* **Data-poisoning contra anomaly detectors.** Chen *et al.* (IEEE S&P 2024) demonstraram que adicionar apenas 3 % de tráfego criado pode deslocar o limite de decisão do Isolation Forest e do ECOD, fazendo com que ataques reais pareçam normais. Os autores lançaram uma PoC open-source (`udo-poison`) que sintetiza automaticamente pontos de poison.<sup>[[2]](#references)</sup>
* **Backdooring de clustering models.** A técnica *BadCME* (BlackHat EU 2023) implanta um pequeno padrão de trigger; sempre que esse trigger aparece, um detector baseado em K-Means coloca silenciosamente o evento dentro de um cluster “benigno”.
* **Evasion de DBSCAN/HDBSCAN.** Um preprint acadêmico de 2025 da KU Leuven mostrou que um atacante pode criar padrões de beaconing que caem propositalmente em lacunas de densidade, escondendo-se efetivamente dentro dos labels de *noise*.

Mitigações que estão ganhando força:

1. **Sanitização do modelo / TRIM.** Antes de cada época de retraining, descartar os 1–2 % de pontos com maior loss (maximum likelihood trimmed) para tornar o poisoning significativamente mais difícil.
2. **Consensus ensembling.** Combinar vários detectors heterogêneos (por exemplo, Isolation Forest + GMM + ECOD) e gerar um alert se qualquer modelo sinalizar um ponto. Pesquisas indicam que isso aumenta o custo do atacante em >10×.
3. **Defesa baseada em distância para clustering.** Recalcular os clusters com `k` seeds aleatórias diferentes e ignorar os pontos que mudam constantemente de cluster.

---

### Ferramentas Open-Source Modernas (2024-2025)

* **PyOD 2.x** (lançado em maio de 2024) adicionou os detectors *ECOD*, *COPOD* e *AutoFormer* acelerados por GPU. Agora ele inclui um subcomando `benchmark` que permite comparar mais de 30 algoritmos no seu dataset com **uma linha de código**:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (fevereiro de 2025) concentra-se em vision, mas também contém uma implementação genérica do **PatchCore** – útil para detecção de phishing pages baseada em screenshots.
* **scikit-learn 1.5** (novembro de 2024) finalmente expõe `score_samples` para *HDBSCAN* por meio do novo wrapper `cluster.HDBSCAN`, portanto você não precisa do pacote contrib externo ao usar Python 3.12.

<details>
<summary>Exemplo rápido de PyOD – ensemble de ECOD + Isolation Forest</summary>
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

## Referências

- [1] [HDBSCAN – Clustering hierárquico baseado em densidade](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* “Sobre a vulnerabilidade da detecção de anomalias não supervisionada a data poisoning.” *Simpósio IEEE sobre Segurança e Privacidade*, 2024.



{{#include ../banners/hacktricks-training.md}}
