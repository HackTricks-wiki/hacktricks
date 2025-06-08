# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning

Deep learning é um subconjunto de machine learning que utiliza redes neurais com múltiplas camadas (redes neurais profundas) para modelar padrões complexos em dados. Ele alcançou um sucesso notável em vários domínios, incluindo visão computacional, processamento de linguagem natural e reconhecimento de fala.

### Neural Networks

Redes neurais são os blocos de construção do deep learning. Elas consistem em nós interconectados (neurônios) organizados em camadas. Cada neurônio recebe entradas, aplica uma soma ponderada e passa o resultado por uma função de ativação para produzir uma saída. As camadas podem ser categorizadas da seguinte forma:
- **Input Layer**: A primeira camada que recebe os dados de entrada.
- **Hidden Layers**: Camadas intermediárias que realizam transformações nos dados de entrada. O número de camadas ocultas e neurônios em cada camada pode variar, levando a diferentes arquiteturas.
- **Output Layer**: A camada final que produz a saída da rede, como probabilidades de classe em tarefas de classificação.

### Activation Functions

Quando uma camada de neurônios processa dados de entrada, cada neurônio aplica um peso e um viés à entrada (`z = w * x + b`), onde `w` é o peso, `x` é a entrada e `b` é o viés. A saída do neurônio é então passada por uma **função de ativação para introduzir não-linearidade** no modelo. Essa função de ativação basicamente indica se o próximo neurônio "deve ser ativado e quanto". Isso permite que a rede aprenda padrões e relações complexas nos dados, permitindo que ela aproxime qualquer função contínua.

Portanto, as funções de ativação introduzem não-linearidade na rede neural, permitindo que ela aprenda relações complexas nos dados. Funções de ativação comuns incluem:
- **Sigmoid**: Mapeia valores de entrada para uma faixa entre 0 e 1, frequentemente usada em classificação binária.
- **ReLU (Rectified Linear Unit)**: Produz a entrada diretamente se for positiva; caso contrário, produz zero. É amplamente utilizada devido à sua simplicidade e eficácia no treinamento de redes profundas.
- **Tanh**: Mapeia valores de entrada para uma faixa entre -1 e 1, frequentemente usada em camadas ocultas.
- **Softmax**: Converte pontuações brutas em probabilidades, frequentemente usada na camada de saída para classificação multi-classe.

### Backpropagation

Backpropagation é o algoritmo usado para treinar redes neurais ajustando os pesos das conexões entre neurônios. Ele funciona calculando o gradiente da função de perda em relação a cada peso e atualizando os pesos na direção oposta do gradiente para minimizar a perda. Os passos envolvidos na backpropagation são:

1. **Forward Pass**: Calcular a saída da rede passando a entrada pelas camadas e aplicando funções de ativação.
2. **Loss Calculation**: Calcular a perda (erro) entre a saída prevista e o verdadeiro alvo usando uma função de perda (por exemplo, erro quadrático médio para regressão, entropia cruzada para classificação).
3. **Backward Pass**: Calcular os gradientes da perda em relação a cada peso usando a regra da cadeia do cálculo.
4. **Weight Update**: Atualizar os pesos usando um algoritmo de otimização (por exemplo, descida de gradiente estocástica, Adam) para minimizar a perda.

## Convolutional Neural Networks (CNNs)

Redes Neurais Convolucionais (CNNs) são um tipo especializado de rede neural projetada para processar dados em grade, como imagens. Elas são particularmente eficazes em tarefas de visão computacional devido à sua capacidade de aprender automaticamente hierarquias espaciais de características.

Os principais componentes das CNNs incluem:
- **Convolutional Layers**: Aplicam operações de convolução aos dados de entrada usando filtros (kernels) aprendíveis para extrair características locais. Cada filtro desliza sobre a entrada e calcula um produto escalar, produzindo um mapa de características.
- **Pooling Layers**: Reduzem as dimensões espaciais dos mapas de características enquanto retêm características importantes. Operações de pooling comuns incluem max pooling e average pooling.
- **Fully Connected Layers**: Conectam cada neurônio em uma camada a cada neurônio na próxima camada, semelhante às redes neurais tradicionais. Essas camadas são tipicamente usadas no final da rede para tarefas de classificação.

Dentro de uma CNN **`Convolutional Layers`**, também podemos distinguir entre:
- **Initial Convolutional Layer**: A primeira camada convolucional que processa os dados de entrada brutos (por exemplo, uma imagem) e é útil para identificar características básicas como bordas e texturas.
- **Intermediate Convolutional Layers**: Camadas convolucionais subsequentes que se baseiam nas características aprendidas pela camada inicial, permitindo que a rede aprenda padrões e representações mais complexas.
- **Final Convolutional Layer**: As últimas camadas convolucionais antes das camadas totalmente conectadas, que capturam características de alto nível e preparam os dados para classificação.

> [!TIP]
> CNNs são particularmente eficazes para classificação de imagens, detecção de objetos e tarefas de segmentação de imagens devido à sua capacidade de aprender hierarquias espaciais de características em dados em grade e reduzir o número de parâmetros por meio do compartilhamento de pesos.
> Além disso, elas funcionam melhor com dados que suportam o princípio da localidade de características, onde dados vizinhos (pixels) são mais propensos a estar relacionados do que pixels distantes, o que pode não ser o caso para outros tipos de dados, como texto.
> Além disso, observe como as CNNs serão capazes de identificar até mesmo características complexas, mas não serão capazes de aplicar nenhum contexto espacial, significando que a mesma característica encontrada em diferentes partes da imagem será a mesma.

### Example defining a CNN

*Aqui você encontrará uma descrição de como definir uma Rede Neural Convolucional (CNN) em PyTorch que começa com um lote de imagens RGB como conjunto de dados de tamanho 48x48 e usa camadas convolucionais e maxpool para extrair características, seguidas por camadas totalmente conectadas para classificação.*

Esta é a forma como você pode definir 1 camada convolucional em PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Número de canais de entrada. No caso de imagens RGB, isso é 3 (um para cada canal de cor). Se você estiver trabalhando com imagens em escala de cinza, isso seria 1.

- `out_channels`: Número de canais de saída (filtros) que a camada convolucional aprenderá. Este é um hiperparâmetro que você pode ajustar com base na arquitetura do seu modelo.

- `kernel_size`: Tamanho do filtro convolucional. Uma escolha comum é 3x3, o que significa que o filtro cobrirá uma área de 3x3 da imagem de entrada. Isso é como um carimbo de cor 3×3×3 que é usado para gerar os out_channels a partir dos in_channels:
1. Coloque esse carimbo 3×3×3 no canto superior esquerdo do cubo da imagem.
2. Multiplique cada peso pelo pixel abaixo dele, some todos, adicione o viés → você obtém um número.
3. Escreva esse número em um mapa em branco na posição (0, 0).
4. Deslize o carimbo um pixel para a direita (stride = 1) e repita até preencher uma grade inteira de 48×48.

- `padding`: Número de pixels adicionados a cada lado da entrada. O padding ajuda a preservar as dimensões espaciais da entrada, permitindo mais controle sobre o tamanho da saída. Por exemplo, com um kernel de 3x3 e uma entrada de 48x48 pixels, um padding de 1 manterá o tamanho da saída o mesmo (48x48) após a operação de convolução. Isso ocorre porque o padding adiciona uma borda de 1 pixel ao redor da imagem de entrada, permitindo que o kernel deslize sobre as bordas sem reduzir as dimensões espaciais.

Então, o número de parâmetros treináveis nesta camada é:
- (3x3x3 (tamanho do kernel) + 1 (viés)) x 32 (out_channels) = 896 parâmetros treináveis.

Observe que um viés (+1) é adicionado por kernel usado porque a função de cada camada convolucional é aprender uma transformação linear da entrada, que é representada pela equação:
```plaintext
Y = f(W * X + b)
```
onde `W` é a matriz de pesos (os filtros aprendidos, 3x3x3 = 27 parâmetros), `b` é o vetor de viés que é +1 para cada canal de saída.

Note que a saída de `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` será um tensor de forma `(batch_size, 32, 48, 48)`, porque 32 é o novo número de canais gerados de tamanho 48x48 pixels.

Então, poderíamos conectar esta camada convolucional a outra camada convolucional como: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

O que adicionará: (32x3x3 (tamanho do kernel) + 1 (viés)) x 64 (out_channels) = 18.496 parâmetros treináveis e uma saída de forma `(batch_size, 64, 48, 48)`.

Como você pode ver, o **número de parâmetros cresce rapidamente com cada camada convolucional adicional**, especialmente à medida que o número de canais de saída aumenta.

Uma opção para controlar a quantidade de dados usados é usar **max pooling** após cada camada convolucional. O max pooling reduz as dimensões espaciais dos mapas de características, o que ajuda a reduzir o número de parâmetros e a complexidade computacional, mantendo características importantes.

Pode ser declarado como: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Isso basicamente indica usar uma grade de 2x2 pixels e pegar o valor máximo de cada grade para reduzir o tamanho do mapa de características pela metade. Além disso, `stride=2` significa que a operação de pooling se moverá 2 pixels de cada vez, neste caso, prevenindo qualquer sobreposição entre as regiões de pooling.

Com esta camada de pooling, a forma da saída após a primeira camada convolucional seria `(batch_size, 64, 24, 24)` após aplicar `self.pool1` à saída de `self.conv2`, reduzindo o tamanho para 1/4 do que era na camada anterior.

> [!TIP]
> É importante fazer pooling após as camadas convolucionais para reduzir as dimensões espaciais dos mapas de características, o que ajuda a controlar o número de parâmetros e a complexidade computacional, enquanto faz com que o parâmetro inicial aprenda características importantes.
> Você pode ver as convoluções antes de uma camada de pooling como uma forma de extrair características dos dados de entrada (como linhas, bordas), essa informação ainda estará presente na saída agrupada, mas a próxima camada convolucional não poderá ver os dados de entrada originais, apenas a saída agrupada, que é uma versão reduzida da camada anterior com essa informação.
> Na ordem usual: `Conv → ReLU → Pool` cada janela de pooling 2×2 agora compete com ativações de características (“borda presente / não”), não intensidades de pixels brutos. Manter a ativação mais forte realmente mantém a evidência mais saliente.

Então, após adicionar quantas camadas convolucionais e de pooling forem necessárias, podemos achatar a saída para alimentá-la em camadas totalmente conectadas. Isso é feito remodelando o tensor para um vetor 1D para cada amostra no lote:
```python
x = x.view(-1, 64*24*24)
```
E com este vetor 1D com todos os parâmetros de treinamento gerados pelas camadas convolucionais e de pooling anteriores, podemos definir uma camada totalmente conectada como:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Que irá pegar a saída achatada da camada anterior e mapeá-la para 512 unidades ocultas.

Note como esta camada adicionou `(64 * 24 * 24 + 1 (viés)) * 512 = 3,221,504` parâmetros treináveis, o que é um aumento significativo em comparação com as camadas convolucionais. Isso ocorre porque as camadas totalmente conectadas conectam cada neurônio em uma camada a cada neurônio na próxima camada, levando a um grande número de parâmetros.

Finalmente, podemos adicionar uma camada de saída para produzir os logits da classe final:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Isso adicionará `(512 + 1 (bias)) * num_classes` parâmetros treináveis, onde `num_classes` é o número de classes na tarefa de classificação (por exemplo, 43 para o conjunto de dados GTSRB).

Uma prática comum é adicionar uma camada de dropout antes das camadas totalmente conectadas para evitar overfitting. Isso pode ser feito com:
```python
self.dropout = nn.Dropout(0.5)
```
Esta camada define aleatoriamente uma fração das unidades de entrada como zero durante o treinamento, o que ajuda a prevenir o overfitting ao reduzir a dependência de neurônios específicos.

### Exemplo de código CNN
```python
import torch
import torch.nn as nn
import torch.nn.functional as F

class MY_NET(nn.Module):
def __init__(self, num_classes=32):
super(MY_NET, self).__init__()
# Initial conv layer: 3 input channels (RGB), 32 output channels, 3x3 kernel, padding 1
# This layer will learn basic features like edges and textures
self.conv1 = nn.Conv2d(
in_channels=3, out_channels=32, kernel_size=3, padding=1
)
# Output: (Batch Size, 32, 48, 48)

# Conv Layer 2: 32 input channels, 64 output channels, 3x3 kernel, padding 1
# This layer will learn more complex features based on the output of conv1
self.conv2 = nn.Conv2d(
in_channels=32, out_channels=64, kernel_size=3, padding=1
)
# Output: (Batch Size, 64, 48, 48)

# Max Pooling 1: Kernel 2x2, Stride 2. Reduces spatial dimensions by half (1/4th of the previous layer).
self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)
# Output: (Batch Size, 64, 24, 24)

# Conv Layer 3: 64 input channels, 128 output channels, 3x3 kernel, padding 1
# This layer will learn even more complex features based on the output of conv2
# Note that the number of output channels can be adjusted based on the complexity of the task
self.conv3 = nn.Conv2d(
in_channels=64, out_channels=128, kernel_size=3, padding=1
)
# Output: (Batch Size, 128, 24, 24)

# Max Pooling 2: Kernel 2x2, Stride 2. Reduces spatial dimensions by half again.
# Reducing the dimensions further helps to control the number of parameters and computational complexity.
self.pool2 = nn.MaxPool2d(kernel_size=2, stride=2)
# Output: (Batch Size, 128, 12, 12)

# From the second pooling layer, we will flatten the output to feed it into fully connected layers.
# The feature size is calculated as follows:
# Feature size = Number of output channels * Height * Width
self._feature_size = 128 * 12 * 12

# Fully Connected Layer 1 (Hidden): Maps flattened features to hidden units.
# This layer will learn to combine the features extracted by the convolutional layers.
self.fc1 = nn.Linear(self._feature_size, 512)

# Fully Connected Layer 2 (Output): Maps hidden units to class logits.
# Output size MUST match num_classes
self.fc2 = nn.Linear(512, num_classes)

# Dropout layer configuration with a dropout rate of 0.5.
# This layer is used to prevent overfitting by randomly setting a fraction of the input units to zero during training.
self.dropout = nn.Dropout(0.5)

def forward(self, x):
"""
The forward method defines the forward pass of the network.
It takes an input tensor `x` and applies the convolutional layers, pooling layers, and fully connected layers in sequence.
The input tensor `x` is expected to have the shape (Batch Size, Channels, Height, Width), where:
- Batch Size: Number of samples in the batch
- Channels: Number of input channels (e.g., 3 for RGB images)
- Height: Height of the input image (e.g., 48 for 48x48 images)
- Width: Width of the input image (e.g., 48 for 48x48 images)
The output of the forward method is the logits for each class, which can be used for classification tasks.
Args:
x (torch.Tensor): Input tensor of shape (Batch Size, Channels, Height, Width)
Returns:
torch.Tensor: Output tensor of shape (Batch Size, num_classes) containing the class logits.
"""

# Conv1 -> ReLU -> Conv2 -> ReLU -> Pool1 -> Conv3 -> ReLU -> Pool2
x = self.conv1(x)
x = F.relu(x)
x = self.conv2(x)
x = F.relu(x)
x = self.pool1(x)
x = self.conv3(x)
x = F.relu(x)
x = self.pool2(x)
# At this point, x has shape (Batch Size, 128, 12, 12)

# Flatten the output to feed it into fully connected layers
x = torch.flatten(x, 1)

# Apply dropout to prevent overfitting
x = self.dropout(x)

# First FC layer with ReLU activation
x = F.relu(self.fc1(x))

# Apply Dropout again
x = self.dropout(x)
# Final FC layer to get logits
x = self.fc2(x)
# Output shape will be (Batch Size, num_classes)
# Note that the output is not passed through a softmax activation here, as it is typically done in the loss function (e.g., CrossEntropyLoss)
return x
```
### Exemplo de treinamento de código CNN

O seguinte código irá gerar alguns dados de treinamento e treinar o modelo `MY_NET` definido acima. Alguns valores interessantes a serem observados:

- `EPOCHS` é o número de vezes que o modelo verá todo o conjunto de dados durante o treinamento. Se EPOCH for muito pequeno, o modelo pode não aprender o suficiente; se for muito grande, pode ocorrer overfitting.
- `LEARNING_RATE` é o tamanho do passo para o otimizador. Uma taxa de aprendizado pequena pode levar a uma convergência lenta, enquanto uma grande pode ultrapassar a solução ótima e impedir a convergência.
- `WEIGHT_DECAY` é um termo de regularização que ajuda a prevenir o overfitting penalizando pesos grandes.

Sobre o loop de treinamento, aqui estão algumas informações interessantes a saber:
- O `criterion = nn.CrossEntropyLoss()` é a função de perda usada para tarefas de classificação multiclasse. Ela combina a ativação softmax e a perda de entropia cruzada em uma única função, tornando-a adequada para treinar modelos que produzem logits de classe.
- Se o modelo fosse esperado para produzir outros tipos de saídas, como classificação binária ou regressão, usaríamos funções de perda diferentes, como `nn.BCEWithLogitsLoss()` para classificação binária ou `nn.MSELoss()` para regressão.
- O `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inicializa o otimizador Adam, que é uma escolha popular para treinar modelos de deep learning. Ele adapta a taxa de aprendizado para cada parâmetro com base nos primeiros e segundos momentos dos gradientes.
- Outros otimizadores como `optim.SGD` (Stochastic Gradient Descent) ou `optim.RMSprop` também poderiam ser usados, dependendo dos requisitos específicos da tarefa de treinamento.
- O método `model.train()` define o modelo para o modo de treinamento, permitindo que camadas como dropout e normalização em lote se comportem de maneira diferente durante o treinamento em comparação com a avaliação.
- `optimizer.zero_grad()` limpa os gradientes de todos os tensores otimizados antes da passagem reversa, o que é necessário porque os gradientes se acumulam por padrão no PyTorch. Se não forem limpos, os gradientes de iterações anteriores seriam adicionados aos gradientes atuais, levando a atualizações incorretas.
- `loss.backward()` calcula os gradientes da perda em relação aos parâmetros do modelo, que são então usados pelo otimizador para atualizar os pesos.
- `optimizer.step()` atualiza os parâmetros do modelo com base nos gradientes computados e na taxa de aprendizado.
```python
import torch, torch.nn.functional as F
from torch import nn, optim
from torch.utils.data import DataLoader
from torchvision import datasets, transforms
from tqdm import tqdm
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np

# ---------------------------------------------------------------------------
# 1. Globals
# ---------------------------------------------------------------------------
IMG_SIZE      = 48               # model expects 48×48
NUM_CLASSES   = 10               # MNIST has 10 digits
BATCH_SIZE    = 64               # batch size for training and validation
EPOCHS        = 5                # number of training epochs
LEARNING_RATE = 1e-3             # initial learning rate for Adam optimiser
WEIGHT_DECAY  = 1e-4             # L2 regularisation to prevent overfitting

# Channel-wise mean / std for MNIST (grayscale ⇒ repeat for 3-channel input)
MNIST_MEAN = (0.1307, 0.1307, 0.1307)
MNIST_STD  = (0.3081, 0.3081, 0.3081)

# ---------------------------------------------------------------------------
# 2. Transforms
# ---------------------------------------------------------------------------
# 1) Baseline transform: resize + tensor (no colour/aug/no normalise)
transform_base = transforms.Compose([
transforms.Resize((IMG_SIZE, IMG_SIZE)),      # 🔹 Resize – force all images to 48 × 48 so the CNN sees a fixed geometry
transforms.Grayscale(num_output_channels=3),  # 🔹 Grayscale→RGB – MNIST is 1-channel; duplicate into 3 channels for convnet
transforms.ToTensor(),                        # 🔹 ToTensor – convert PIL image [0‒255] → float tensor [0.0‒1.0]
])

# 2) Training transform: augment  + normalise
transform_norm = transforms.Compose([
transforms.Resize((IMG_SIZE, IMG_SIZE)),      # keep 48 × 48 input size
transforms.Grayscale(num_output_channels=3),  # still need 3 channels
transforms.RandomRotation(10),                # 🔹 RandomRotation(±10°) – small tilt ⇢ rotation-invariance, combats overfitting
transforms.ColorJitter(brightness=0.2,
contrast=0.2),         # 🔹 ColorJitter – pseudo-RGB brightness/contrast noise; extra variety
transforms.ToTensor(),                        # convert to tensor before numeric ops
transforms.Normalize(mean=MNIST_MEAN,
std=MNIST_STD),          # 🔹 Normalize – zero-centre & scale so every channel ≈ N(0,1)
])

# 3) Test/validation transform: only resize + normalise (no aug)
transform_test = transforms.Compose([
transforms.Resize((IMG_SIZE, IMG_SIZE)),      # same spatial size as train
transforms.Grayscale(num_output_channels=3),  # match channel count
transforms.ToTensor(),                        # tensor conversion
transforms.Normalize(mean=MNIST_MEAN,
std=MNIST_STD),          # 🔹 keep test data on same scale as training data
])

# ---------------------------------------------------------------------------
# 3. Datasets & loaders
# ---------------------------------------------------------------------------
train_set = datasets.MNIST("data",   train=True,  download=True, transform=transform_norm)
test_set  = datasets.MNIST("data",   train=False, download=True, transform=transform_test)

train_loader = DataLoader(train_set, batch_size=BATCH_SIZE, shuffle=True)
test_loader  = DataLoader(test_set,  batch_size=256,          shuffle=False)

print(f"Training on {len(train_set)} samples, validating on {len(test_set)} samples.")

# ---------------------------------------------------------------------------
# 4. Model / loss / optimiser
# ---------------------------------------------------------------------------
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model  = MY_NET(num_classes=NUM_CLASSES).to(device)

criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)

# ---------------------------------------------------------------------------
# 5. Training loop
# ---------------------------------------------------------------------------
for epoch in range(1, EPOCHS + 1):
model.train()                          # Set model to training mode enabling dropout and batch norm

running_loss = 0.0                     # sums batch losses to compute epoch average
correct      = 0                       # number of correct predictions
total        = 0                       # number of samples seen

# tqdm wraps the loader to show a live progress-bar per epoch
for X_batch, y_batch in tqdm(train_loader, desc=f"Epoch {epoch}", leave=False):
# 3-a) Move data to GPU (if available) ----------------------------------
X_batch, y_batch = X_batch.to(device), y_batch.to(device)

# 3-b) Forward pass -----------------------------------------------------
logits = model(X_batch)            # raw class scores (shape: [B, NUM_CLASSES])
loss   = criterion(logits, y_batch)

# 3-c) Backward pass & parameter update --------------------------------
optimizer.zero_grad()              # clear old gradients
loss.backward()                    # compute new gradients
optimizer.step()                   # gradient → weight update

# 3-d) Statistics -------------------------------------------------------
running_loss += loss.item() * X_batch.size(0)     # sum of (batch loss × batch size)
preds   = logits.argmax(dim=1)                    # predicted class labels
correct += (preds == y_batch).sum().item()        # correct predictions in this batch
total   += y_batch.size(0)                        # samples processed so far

# 3-e) Epoch-level metrics --------------------------------------------------
epoch_loss = running_loss / total
epoch_acc  = 100.0 * correct / total
print(f"[Epoch {epoch}] loss = {epoch_loss:.4f} | accuracy = {epoch_acc:.2f}%")

print("\n✅ Training finished.\n")

# ---------------------------------------------------------------------------
# 6. Evaluation on test set
# ---------------------------------------------------------------------------
model.eval() # Set model to evaluation mode (disables dropout and batch norm)
with torch.no_grad():
logits_all, labels_all = [], []
for X, y in test_loader:
logits_all.append(model(X.to(device)).cpu())
labels_all.append(y)
logits_all = torch.cat(logits_all)
labels_all = torch.cat(labels_all)
preds_all  = logits_all.argmax(1)

test_loss = criterion(logits_all, labels_all).item()
test_acc  = (preds_all == labels_all).float().mean().item() * 100

print(f"Test loss: {test_loss:.4f}")
print(f"Test accuracy: {test_acc:.2f}%\n")

print("Classification report (precision / recall / F1):")
print(classification_report(labels_all, preds_all, zero_division=0))

print("Confusion matrix (rows = true, cols = pred):")
print(confusion_matrix(labels_all, preds_all))
```
## Redes Neurais Recorrentes (RNNs)

Redes Neurais Recorrentes (RNNs) são uma classe de redes neurais projetadas para processar dados sequenciais, como séries temporais ou linguagem natural. Ao contrário das redes neurais tradicionais feedforward, as RNNs têm conexões que se retroalimentam, permitindo que mantenham um estado oculto que captura informações sobre entradas anteriores na sequência.

Os principais componentes das RNNs incluem:
- **Camadas Recorrentes**: Essas camadas processam sequências de entrada um passo de tempo por vez, atualizando seu estado oculto com base na entrada atual e no estado oculto anterior. Isso permite que as RNNs aprendam dependências temporais nos dados.
- **Estado Oculto**: O estado oculto é um vetor que resume as informações dos passos de tempo anteriores. Ele é atualizado a cada passo de tempo e é usado para fazer previsões para a entrada atual.
- **Camada de Saída**: A camada de saída produz as previsões finais com base no estado oculto. Em muitos casos, as RNNs são usadas para tarefas como modelagem de linguagem, onde a saída é uma distribuição de probabilidade sobre a próxima palavra em uma sequência.

Por exemplo, em um modelo de linguagem, a RNN processa uma sequência de palavras, por exemplo, "O gato sentou no" e prevê a próxima palavra com base no contexto fornecido pelas palavras anteriores, neste caso, "tapete".

### Memória de Longo Prazo e Curto Prazo (LSTM) e Unidade Recorrente Gated (GRU)

As RNNs são particularmente eficazes para tarefas que envolvem dados sequenciais, como modelagem de linguagem, tradução automática e reconhecimento de fala. No entanto, elas podem ter dificuldades com **dependências de longo alcance devido a problemas como gradientes que desaparecem**.

Para resolver isso, arquiteturas especializadas como Memória de Longo Prazo e Curto Prazo (LSTM) e Unidade Recorrente Gated (GRU) foram desenvolvidas. Essas arquiteturas introduzem mecanismos de gating que controlam o fluxo de informações, permitindo que capturem dependências de longo alcance de forma mais eficaz.

- **LSTM**: Redes LSTM usam três portas (porta de entrada, porta de esquecimento e porta de saída) para regular o fluxo de informações dentro e fora do estado da célula, permitindo que elas lembrem ou esqueçam informações ao longo de longas sequências. A porta de entrada controla quanto de nova informação adicionar com base na entrada e no estado oculto anterior, a porta de esquecimento controla quanto de informação descartar. Combinando a porta de entrada e a porta de esquecimento, obtemos o novo estado. Finalmente, combinando o novo estado da célula, com a entrada e o estado oculto anterior, também obtemos o novo estado oculto.
- **GRU**: Redes GRU simplificam a arquitetura LSTM combinando as portas de entrada e de esquecimento em uma única porta de atualização, tornando-as computacionalmente mais eficientes enquanto ainda capturam dependências de longo alcance.

## LLMs (Modelos de Linguagem Grande)

Modelos de Linguagem Grande (LLMs) são um tipo de modelo de aprendizado profundo especificamente projetado para tarefas de processamento de linguagem natural. Eles são treinados em grandes quantidades de dados textuais e podem gerar texto semelhante ao humano, responder perguntas, traduzir idiomas e realizar várias outras tarefas relacionadas à linguagem. 
Os LLMs são tipicamente baseados em arquiteturas de transformadores, que usam mecanismos de autoatenção para capturar relacionamentos entre palavras em uma sequência, permitindo que entendam o contexto e gerem texto coerente.

### Arquitetura Transformer
A arquitetura transformer é a base de muitos LLMs. Ela consiste em uma estrutura de codificador-decodificador, onde o codificador processa a sequência de entrada e o decodificador gera a sequência de saída. Os componentes-chave da arquitetura transformer incluem:
- **Mecanismo de Autoatenção**: Este mecanismo permite que o modelo pese a importância de diferentes palavras em uma sequência ao gerar representações. Ele calcula pontuações de atenção com base nos relacionamentos entre palavras, permitindo que o modelo se concentre no contexto relevante.
- **Atenção Multi-Cabeça**: Este componente permite que o modelo capture múltiplos relacionamentos entre palavras usando múltiplas cabeças de atenção, cada uma focando em diferentes aspectos da entrada.
- **Codificação Posicional**: Como os transformadores não têm uma noção embutida de ordem das palavras, a codificação posicional é adicionada às incorporações de entrada para fornecer informações sobre a posição das palavras na sequência.

## Modelos de Difusão
Modelos de difusão são uma classe de modelos generativos que aprendem a gerar dados simulando um processo de difusão. Eles são particularmente eficazes para tarefas como geração de imagens e ganharam popularidade nos últimos anos. 
Os modelos de difusão funcionam transformando gradualmente uma distribuição de ruído simples em uma distribuição de dados complexa através de uma série de etapas de difusão. Os componentes-chave dos modelos de difusão incluem:
- **Processo de Difusão Direta**: Este processo adiciona gradualmente ruído aos dados, transformando-os em uma distribuição de ruído simples. O processo de difusão direta é tipicamente definido por uma série de níveis de ruído, onde cada nível corresponde a uma quantidade específica de ruído adicionada aos dados.
- **Processo de Difusão Reversa**: Este processo aprende a reverter o processo de difusão direta, gradualmente removendo o ruído dos dados para gerar amostras da distribuição alvo. O processo de difusão reversa é treinado usando uma função de perda que incentiva o modelo a reconstruir os dados originais a partir de amostras ruidosas.

Além disso, para gerar uma imagem a partir de um prompt de texto, os modelos de difusão normalmente seguem estas etapas:
1. **Codificação de Texto**: O prompt de texto é codificado em uma representação latente usando um codificador de texto (por exemplo, um modelo baseado em transformador). Esta representação captura o significado semântico do texto.
2. **Amostragem de Ruído**: Um vetor de ruído aleatório é amostrado de uma distribuição Gaussiana.
3. **Etapas de Difusão**: O modelo aplica uma série de etapas de difusão, transformando gradualmente o vetor de ruído em uma imagem que corresponde ao prompt de texto. Cada etapa envolve a aplicação de transformações aprendidas para remover o ruído da imagem.

{{#include ../banners/hacktricks-training.md}}
