# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning <sup>[[1]](#references)</sup>

Deep learning é um subconjunto de machine learning que usa redes neurais com várias camadas (redes neurais profundas) para modelar padrões complexos em dados. Ele alcançou sucesso notável em vários domínios, incluindo visão computacional, processamento de linguagem natural e reconhecimento de fala.

### Redes Neurais

As redes neurais são os blocos de construção do deep learning. Elas consistem em nós interconectados (neurônios) organizados em camadas. Cada neurônio recebe entradas, aplica uma soma ponderada e passa o resultado por uma função de ativação para produzir uma saída. As camadas podem ser categorizadas da seguinte forma:
- **Camada de Entrada**: A primeira camada, que recebe os dados de entrada.
- **Camadas Ocultas**: Camadas intermediárias que realizam transformações nos dados de entrada. O número de camadas ocultas e de neurônios em cada camada pode variar, resultando em diferentes arquiteturas.
- **Camada de Saída**: A camada final que produz a saída da rede, como probabilidades de classe em tarefas de classificação.


### Funções de Ativação

Quando uma camada de neurônios processa dados de entrada, cada neurônio aplica um peso e um bias à entrada (`z = w * x + b`), onde `w` é o peso, `x` é a entrada e `b` é o bias. A saída do neurônio é então passada por uma **função de ativação para introduzir não linearidade** no modelo. Essa função de ativação basicamente indica se o próximo neurônio "deve ser ativado e em que intensidade". Isso permite que a rede aprenda padrões e relações complexos nos dados, possibilitando a aproximação de qualquer função contínua.

Portanto, as funções de ativação introduzem não linearidade na rede neural, permitindo que ela aprenda relações complexas nos dados. As funções de ativação comuns incluem:
- **Sigmoid**: Mapeia os valores de entrada para um intervalo entre 0 e 1, sendo frequentemente usada em classificação binária.
- **ReLU (Rectified Linear Unit)**: Produz a entrada diretamente se ela for positiva; caso contrário, produz zero. É amplamente usada devido à sua simplicidade e eficácia no treinamento de redes profundas.
- **Tanh**: Mapeia os valores de entrada para um intervalo entre -1 e 1, sendo frequentemente usada em camadas ocultas.
- **Softmax**: Converte pontuações brutas em probabilidades, sendo frequentemente usada na camada de saída para classificação multiclasse.

### Backpropagation

Backpropagation é o algoritmo usado para treinar redes neurais ajustando os pesos das conexões entre os neurônios. Ele funciona calculando o gradiente da função de perda em relação a cada peso e atualizando os pesos na direção oposta à do gradiente para minimizar a perda. As etapas envolvidas no backpropagation são:

1. **Forward Pass**: Calcula a saída da rede passando a entrada pelas camadas e aplicando funções de ativação.
2. **Cálculo da Perda**: Calcula a perda (erro) entre a saída prevista e o alvo verdadeiro usando uma função de perda (por exemplo, erro quadrático médio para regressão, entropia cruzada para classificação).
3. **Backward Pass**: Calcula os gradientes da perda em relação a cada peso usando a regra da cadeia do cálculo.
4. **Atualização dos Pesos**: Atualiza os pesos usando um algoritmo de otimização (por exemplo, stochastic gradient descent, Adam) para minimizar a perda.

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Convolutional Neural Networks (CNNs) são um tipo especializado de rede neural projetado para processar dados em formato de grade, como imagens. Elas são particularmente eficazes em tarefas de visão computacional devido à sua capacidade de aprender automaticamente hierarquias espaciais de características.

Os principais componentes das CNNs incluem:
- **Camadas Convolucionais**: Aplicam operações de convolução aos dados de entrada usando filtros treináveis (kernels) para extrair características locais. Cada filtro desliza sobre a entrada e calcula um produto escalar, produzindo um mapa de características.
- **Camadas de Pooling**: Reduzem os mapas de características para diminuir suas dimensões espaciais enquanto retêm características importantes. As operações de pooling comuns incluem max pooling e average pooling.
- **Camadas Totalmente Conectadas**: Conectam cada neurônio de uma camada a cada neurônio da camada seguinte, de forma semelhante às redes neurais tradicionais. Essas camadas normalmente são usadas no final da rede para tarefas de classificação.

Dentro das **`Convolutional Layers`** de uma CNN, também podemos distinguir entre:
- **Camada Convolucional Inicial**: A primeira camada convolucional que processa os dados brutos de entrada (por exemplo, uma imagem) e é útil para identificar características básicas, como bordas e texturas.
- **Camadas Convolucionais Intermediárias**: Camadas convolucionais subsequentes que se baseiam nas características aprendidas pela camada inicial, permitindo que a rede aprenda padrões e representações mais complexos.
- **Camada Convolucional Final**: As últimas camadas convolucionais antes das camadas totalmente conectadas, que capturam características de alto nível e preparam os dados para a classificação.

> [!TIP]
> As CNNs são particularmente eficazes para tarefas de classificação de imagens, detecção de objetos e segmentação de imagens devido à sua capacidade de aprender hierarquias espaciais de características em dados organizados em formato de grade e reduzir o número de parâmetros por meio do compartilhamento de pesos.
> Além disso, elas funcionam melhor com dados que seguem o princípio da localidade das características, segundo o qual dados vizinhos (pixels) têm maior probabilidade de estar relacionados do que pixels distantes, o que pode não ocorrer com outros tipos de dados, como texto.
> Ademais, observe que as CNNs conseguem identificar até mesmo características complexas, mas não conseguem aplicar contexto espacial, o que significa que a mesma característica encontrada em diferentes partes da imagem será considerada igual.

### Exemplo de definição de uma CNN

*Aqui você encontrará uma descrição de como definir uma Convolutional Neural Network (CNN) em PyTorch que começa com um batch de imagens RGB como dataset de tamanho 48x48 e usa camadas convolucionais e maxpool para extrair características, seguidas por camadas totalmente conectadas para classificação.*

É assim que você pode definir 1 camada convolucional no PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Número de canais de entrada. No caso de imagens RGB, esse número é 3 (um para cada canal de cor). Se você estiver trabalhando com imagens em escala de cinza, esse número será 1.

- `out_channels`: Número de canais de saída (filtros) que a camada convolucional aprenderá. Esse é um hyperparameter que você pode ajustar com base na arquitetura do seu modelo.

- `kernel_size`: Tamanho do filtro convolucional. Uma escolha comum é 3x3, o que significa que o filtro cobrirá uma área de 3x3 da imagem de entrada. Isso é como um carimbo colorido 3×3×3 usado para gerar os out_channels a partir dos in_channels:
1. Coloque esse carimbo 3×3×3 no canto superior esquerdo do cubo da imagem.
2. Multiplique cada peso pelo pixel abaixo dele, some todos os valores e adicione o bias → você obterá um número.
3. Escreva esse número em um mapa vazio na posição (0, 0).
4. Deslize o carimbo um pixel para a direita (stride = 1) e repita até preencher uma grade inteira de 48×48.

- `padding`: Número de pixels adicionados a cada lado da entrada. O padding ajuda a preservar as dimensões espaciais da entrada, permitindo maior controle sobre o tamanho da saída. Por exemplo, com um kernel 3x3 e uma entrada de 48x48 pixels, um padding de 1 manterá o mesmo tamanho da saída (48x48) após a operação de convolução. Isso ocorre porque o padding adiciona uma borda de 1 pixel ao redor da imagem de entrada, permitindo que o kernel deslize sobre as bordas sem reduzir as dimensões espaciais.

Então, o número de parâmetros treináveis nessa camada é:
- (3x3x3 (tamanho do kernel) + 1 (bias)) x 32 (out_channels) = 896 parâmetros treináveis.

Observe que um Bias (+1) é adicionado por kernel usado porque a função de cada camada convolucional é aprender uma transformação linear da entrada, representada pela equação:
```plaintext
Y = f(W * X + b)
```
onde `W` é a matriz de pesos (os filtros aprendidos, 3x3x3 = 27 parâmetros), `b` é o vetor de bias, que é +1 para cada canal de saída.

Observe que a saída de `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` será um tensor com formato `(batch_size, 32, 48, 48)`, pois 32 é o novo número de canais gerados, com tamanho de 48x48 pixels.

Então, poderíamos conectar essa camada convolucional a outra camada convolucional, como: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Isso adicionará: (32x3x3 (tamanho do kernel) + 1 (bias)) x 64 (out_channels) = 18,496 parâmetros treináveis e uma saída com formato `(batch_size, 64, 48, 48)`.

Como você pode ver, o **número de parâmetros cresce rapidamente a cada camada convolucional adicional**, especialmente à medida que o número de canais de saída aumenta.

Uma opção para controlar a quantidade de dados utilizada é usar **max pooling** após cada camada convolucional. O max pooling reduz as dimensões espaciais dos mapas de características, ajudando a reduzir o número de parâmetros e a complexidade computacional, enquanto preserva características importantes.

Ele pode ser declarado como: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Isso basicamente indica o uso de uma grade de 2x2 pixels e a seleção do maior valor de cada grade para reduzir pela metade o tamanho do mapa de características. Além disso, `stride=2` significa que a operação de pooling avançará 2 pixels por vez, impedindo, neste caso, qualquer sobreposição entre as regiões de pooling.

Com essa camada de pooling, o formato da saída após a primeira camada convolucional seria `(batch_size, 64, 24, 24)` após aplicar `self.pool1` à saída de `self.conv2`, reduzindo o tamanho para 1/4 do tamanho da camada anterior.

> [!TIP]
> É importante aplicar pooling após as camadas convolucionais para reduzir as dimensões espaciais dos mapas de características, o que ajuda a controlar o número de parâmetros e a complexidade computacional, além de permitir que o parâmetro inicial aprenda características importantes.
>Você pode ver as convoluções antes de uma camada de pooling como uma forma de extrair características dos dados de entrada (como linhas e bordas). Essas informações ainda estarão presentes na saída após o pooling, mas a próxima camada convolucional não poderá ver os dados de entrada originais, apenas a saída após o pooling, que é uma versão reduzida da camada anterior contendo essas informações.
>Na ordem usual: `Conv → ReLU → Pool`, cada janela de pooling 2×2 agora processa ativações de características (“borda presente / ausente”), e não intensidades brutas de pixels. Manter a ativação mais forte realmente preserva a evidência mais relevante.

Depois de adicionar quantas camadas convolucionais e de pooling forem necessárias, podemos achatar a saída para alimentá-la em camadas totalmente conectadas. Isso é feito remodelando o tensor em um vetor 1D para cada amostra do batch:
```python
x = x.view(-1, 64*24*24)
```
E, com este vetor 1D contendo todos os parâmetros de treinamento gerados pelas camadas convolucionais e de pooling anteriores, podemos definir uma camada totalmente conectada, como:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Que receberá a saída achatada da camada anterior e a mapeará para 512 unidades ocultas.

Observe como essa camada adicionou `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` parâmetros treináveis, o que representa um aumento significativo em comparação com as camadas convolucionais. Isso ocorre porque as camadas totalmente conectadas conectam cada neurônio de uma camada a cada neurônio da camada seguinte, resultando em um grande número de parâmetros.

Por fim, podemos adicionar uma camada de saída para produzir os logits finais das classes:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Isso adicionará `(512 + 1 (bias)) * num_classes` parâmetros treináveis, onde `num_classes` é o número de classes na tarefa de classificação (por exemplo, 43 para o conjunto de dados GTSRB).

Outra prática comum é adicionar uma camada de dropout antes das camadas totalmente conectadas para evitar overfitting. Isso pode ser feito com:
```python
self.dropout = nn.Dropout(0.5)
```
Essa camada define aleatoriamente uma fração das unidades de entrada como zero durante o treinamento, o que ajuda a evitar overfitting ao reduzir a dependência de neurônios específicos.

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

O código a seguir criará alguns dados de treinamento e treinará o modelo `MY_NET` definido acima. Alguns valores interessantes a serem observados:

- `EPOCHS` é o número de vezes que o modelo verá todo o dataset durante o treinamento. Se EPOCH for muito pequeno, o modelo pode não aprender o suficiente; se for muito grande, pode sofrer overfitting.
- `LEARNING_RATE` é o tamanho do passo do optimizer. Uma learning rate pequena pode levar a uma convergência lenta, enquanto uma grande pode ultrapassar a solução ideal e impedir a convergência.
- `WEIGHT_DECAY` é um termo de regularização que ajuda a evitar overfitting ao penalizar pesos grandes.

Sobre o training loop, estas são algumas informações interessantes:

- `criterion = nn.CrossEntropyLoss()` é a loss function usada para tarefas de classificação multiclasse. Ela combina a ativação softmax e a cross-entropy loss em uma única função, tornando-a adequada para treinar modelos que produzem class logits.
- Se o modelo devesse produzir outros tipos de outputs, como classificação binária ou regressão, usaríamos loss functions diferentes, como `nn.BCEWithLogitsLoss()` para classificação binária ou `nn.MSELoss()` para regressão.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inicializa o Adam optimizer, uma opção popular para treinar modelos de deep learning. Ele adapta a learning rate para cada parâmetro com base no primeiro e no segundo momentos dos gradients.
- Outros optimizers, como `optim.SGD` (Stochastic Gradient Descent) ou `optim.RMSprop`, também poderiam ser usados, dependendo dos requisitos específicos da tarefa de treinamento.
- O método `model.train()` coloca o modelo no training mode, fazendo com que layers como dropout e batch normalization se comportem de maneira diferente durante o treinamento em comparação com a avaliação.
- `optimizer.zero_grad()` limpa os gradients de todos os tensors otimizados antes do backward pass, o que é necessário porque os gradients se acumulam por padrão no PyTorch. Se não forem limpos, os gradients de iterações anteriores seriam adicionados aos gradients atuais, levando a updates incorretos.
- `loss.backward()` calcula os gradients da loss em relação aos parâmetros do modelo, que são então usados pelo optimizer para atualizar os pesos.
- `optimizer.step()` atualiza os parâmetros do modelo com base nos gradients calculados e na learning rate.
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
## Redes Neurais Recorrentes (RNNs) <sup>[[3]](#references)</sup>

As Redes Neurais Recorrentes (RNNs) são uma classe de redes neurais projetadas para processar dados sequenciais, como séries temporais ou linguagem natural. Diferentemente das redes neurais feedforward tradicionais, as RNNs têm conexões que fazem loop sobre si mesmas, permitindo que mantenham um estado oculto que captura informações sobre entradas anteriores na sequência.

Os principais componentes das RNNs incluem:
- **Camadas Recorrentes**: Essas camadas processam sequências de entrada um passo de tempo por vez, atualizando seu estado oculto com base na entrada atual e no estado oculto anterior. Isso permite que as RNNs aprendam dependências temporais nos dados.
- **Estado Oculto**: O estado oculto é um vetor que resume as informações dos passos de tempo anteriores. Ele é atualizado a cada passo de tempo e usado para fazer previsões para a entrada atual.
- **Camada de Saída**: A camada de saída produz as previsões finais com base no estado oculto. Em muitos casos, as RNNs são usadas para tarefas como modelagem de linguagem, nas quais a saída é uma distribuição de probabilidade sobre a próxima palavra em uma sequência.

Por exemplo, em um modelo de linguagem, a RNN processa uma sequência de palavras, por exemplo, "The cat sat on the" e prevê a próxima palavra com base no contexto fornecido pelas palavras anteriores, neste caso, "mat".

### Long Short-Term Memory (LSTM) e Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

As RNNs são particularmente eficazes para tarefas que envolvem dados sequenciais, como modelagem de linguagem, tradução automática e reconhecimento de fala. No entanto, elas podem ter dificuldades com **dependências de longo alcance devido a problemas como gradientes que desaparecem**.

Para resolver isso, arquiteturas especializadas como Long Short-Term Memory (LSTM) e Gated Recurrent Unit (GRU) foram desenvolvidas. Essas arquiteturas introduzem mecanismos de gating que controlam o fluxo de informações, permitindo que capturem dependências de longo alcance com mais eficácia.

- **LSTM**: As redes LSTM usam três gates (input gate, forget gate e output gate) para regular o fluxo de informações para dentro e para fora do estado da célula, permitindo que se lembrem ou esqueçam informações ao longo de sequências extensas. O input gate controla quanta informação nova deve ser adicionada com base na entrada e no estado oculto anterior; o forget gate controla quanta informação deve ser descartada. Combinando o input gate e o forget gate, obtemos o novo estado. Por fim, combinando o novo estado da célula com a entrada e o estado oculto anterior, também obtemos o novo estado oculto.
- **GRU**: As redes GRU simplificam a arquitetura LSTM combinando os input e forget gates em um único update gate, tornando-as computacionalmente mais eficientes e, ao mesmo tempo, mantendo a capacidade de capturar dependências de longo alcance.

## LLMs (Large Language Models)

Os Large Language Models (LLMs) são um tipo de modelo de deep learning projetado especificamente para tarefas de processamento de linguagem natural. Eles são treinados com grandes quantidades de dados de texto e podem gerar textos semelhantes aos humanos, responder a perguntas, traduzir idiomas e realizar várias outras tarefas relacionadas à linguagem.
Os LLMs geralmente são baseados em arquiteturas de transformer, que usam mecanismos de self-attention para capturar relações entre palavras em uma sequência, permitindo que compreendam o contexto e gerem textos coerentes.

### Arquitetura de Transformer <sup>[[4]](#references)</sup>
A arquitetura de transformer é a base de muitos LLMs. Ela consiste em uma estrutura encoder-decoder, na qual o encoder processa a sequência de entrada e o decoder gera a sequência de saída. Os principais componentes da arquitetura de transformer incluem:
- **Mecanismo de Self-Attention**: Esse mecanismo permite que o modelo pondere a importância de diferentes palavras em uma sequência ao gerar representações. Ele calcula scores de attention com base nas relações entre as palavras, permitindo que o modelo se concentre no contexto relevante.
- **Multi-Head Attention**: Esse componente permite que o modelo capture múltiplas relações entre as palavras usando várias attention heads, cada uma focada em diferentes aspectos da entrada.
- **Codificação Posicional**: Como os transformers não têm uma noção integrada da ordem das palavras, a codificação posicional é adicionada aos embeddings de entrada para fornecer informações sobre a posição das palavras na sequência.

## Modelos de Diffusion <sup>[[5]](#references)</sup>
Os modelos de diffusion são uma classe de modelos generativos que aprendem a gerar dados simulando um processo de diffusion. Eles são particularmente eficazes para tarefas como geração de imagens e ganharam popularidade nos últimos anos.
Os modelos de diffusion funcionam transformando gradualmente uma distribuição simples de ruído em uma distribuição de dados complexa por meio de uma série de etapas de diffusion. Os principais componentes dos modelos de diffusion incluem:
- **Processo de Diffusion Forward**: Esse processo adiciona gradualmente ruído aos dados, transformando-os em uma distribuição simples de ruído. O processo de diffusion forward normalmente é definido por uma série de níveis de ruído, em que cada nível corresponde a uma quantidade específica de ruído adicionada aos dados.
- **Processo de Diffusion Reverso**: Esse processo aprende a reverter o processo de diffusion forward, removendo gradualmente o ruído dos dados para gerar amostras da distribuição-alvo. O processo de diffusion reverso é treinado usando uma loss function que incentiva o modelo a reconstruir os dados originais a partir de amostras ruidosas.

Além disso, para gerar uma imagem a partir de um prompt de texto, os modelos de diffusion normalmente seguem estas etapas:
1. **Codificação do Texto**: O prompt de texto é codificado em uma representação latente usando um text encoder (por exemplo, um modelo baseado em transformer). Essa representação captura o significado semântico do texto.
2. **Amostragem de Ruído**: Um vetor de ruído aleatório é amostrado de uma distribuição Gaussiana.
3. **Etapas de Diffusion**: O modelo aplica uma série de etapas de diffusion, transformando gradualmente o vetor de ruído em uma imagem correspondente ao prompt de texto. Cada etapa envolve a aplicação de transformações aprendidas para remover o ruído da imagem.

## References

- [1] [PyTorch - Tutorial de Redes Neurais](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Modelos Probabilísticos de Diffusion para Remoção de Ruído](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
