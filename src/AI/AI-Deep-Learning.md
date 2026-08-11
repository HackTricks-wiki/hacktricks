# Aprendizaje profundo

{{#include ../banners/hacktricks-training.md}}

## Aprendizaje profundo <sup>[[1]](#references)</sup>

El aprendizaje profundo es un subconjunto del aprendizaje automático que utiliza redes neuronales con múltiples capas (redes neuronales profundas) para modelar patrones complejos en los datos. Ha logrado un éxito notable en diversos dominios, incluidos la visión artificial, el procesamiento del lenguaje natural y el reconocimiento de voz.

### Redes neuronales

Las redes neuronales son los componentes básicos del aprendizaje profundo. Están formadas por nodos interconectados (neuronas) organizados en capas. Cada neurona recibe entradas, aplica una suma ponderada y pasa el resultado por una función de activación para producir una salida. Las capas se pueden clasificar de la siguiente manera:
- **Capa de entrada**: La primera capa que recibe los datos de entrada.
- **Capas ocultas**: Capas intermedias que realizan transformaciones sobre los datos de entrada. El número de capas ocultas y de neuronas en cada capa puede variar, dando lugar a diferentes arquitecturas.
- **Capa de salida**: La capa final que produce la salida de la red, como las probabilidades de clase en tareas de clasificación.


### Funciones de activación

Cuando una capa de neuronas procesa datos de entrada, cada neurona aplica un peso y un sesgo a la entrada (`z = w * x + b`), donde `w` es el peso, `x` es la entrada y `b` es el sesgo. A continuación, la salida de la neurona pasa por una **función de activación para introducir no linealidad** en el modelo. Esta función de activación básicamente indica si la siguiente neurona "debería activarse y en qué medida". Esto permite que la red aprenda patrones y relaciones complejos en los datos, lo que le permite aproximar cualquier función continua.

Por lo tanto, las funciones de activación introducen no linealidad en la red neuronal, permitiéndole aprender relaciones complejas en los datos. Entre las funciones de activación comunes se incluyen:
- **Sigmoid**: Asigna los valores de entrada a un rango entre 0 y 1; se utiliza habitualmente en la clasificación binaria.
- **ReLU (Rectified Linear Unit)**: Devuelve directamente la entrada si es positiva; de lo contrario, devuelve cero. Se utiliza ampliamente por su simplicidad y eficacia al entrenar redes profundas.
- **Tanh**: Asigna los valores de entrada a un rango entre -1 y 1; se utiliza habitualmente en las capas ocultas.
- **Softmax**: Convierte las puntuaciones sin procesar en probabilidades; se utiliza habitualmente en la capa de salida para la clasificación multiclase.

### Backpropagation

Backpropagation es el algoritmo utilizado para entrenar redes neuronales ajustando los pesos de las conexiones entre las neuronas. Funciona calculando el gradiente de la función de pérdida con respecto a cada peso y actualizando los pesos en la dirección opuesta al gradiente para minimizar la pérdida. Los pasos implicados en Backpropagation son:

1. **Forward Pass**: Calcula la salida de la red pasando la entrada por las capas y aplicando funciones de activación.
2. **Cálculo de la pérdida**: Calcula la pérdida (error) entre la salida predicha y el objetivo real utilizando una función de pérdida (por ejemplo, el error cuadrático medio para la regresión o la entropía cruzada para la clasificación).
3. **Backward Pass**: Calcula los gradientes de la pérdida con respecto a cada peso utilizando la regla de la cadena del cálculo.
4. **Actualización de los pesos**: Actualiza los pesos mediante un algoritmo de optimización (por ejemplo, el descenso de gradiente estocástico o Adam) para minimizar la pérdida.

## Redes neuronales convolucionales (CNNs) <sup>[[2]](#references)</sup>

Las redes neuronales convolucionales (CNNs) son un tipo especializado de red neuronal diseñado para procesar datos estructurados en forma de cuadrícula, como las imágenes. Son especialmente eficaces en tareas de visión artificial debido a su capacidad para aprender automáticamente jerarquías espaciales de características.

Los componentes principales de las CNNs incluyen:
- **Capas convolucionales**: Aplican operaciones de convolución a los datos de entrada utilizando filtros aprendibles (kernels) para extraer características locales. Cada filtro se desliza sobre la entrada y calcula un producto escalar, produciendo un mapa de características.
- **Capas de pooling**: Reducen la resolución de los mapas de características para disminuir sus dimensiones espaciales, conservando al mismo tiempo las características importantes. Entre las operaciones de pooling comunes se incluyen max pooling y average pooling.
- **Capas totalmente conectadas**: Conectan cada neurona de una capa con cada neurona de la siguiente, de forma similar a las redes neuronales tradicionales. Estas capas suelen utilizarse al final de la red para tareas de clasificación.

Dentro de las **`Convolutional Layers`** de una CNN, también podemos distinguir entre:
- **Capa convolucional inicial**: La primera capa convolucional que procesa los datos de entrada sin procesar (por ejemplo, una imagen) y es útil para identificar características básicas como bordes y texturas.
- **Capas convolucionales intermedias**: Capas convolucionales posteriores que se basan en las características aprendidas por la capa inicial, permitiendo que la red aprenda patrones y representaciones más complejos.
- **Capa convolucional final**: Las últimas capas convolucionales antes de las capas totalmente conectadas, que capturan características de alto nivel y preparan los datos para la clasificación.

> [!TIP]
> Las CNNs son especialmente eficaces para tareas de clasificación de imágenes, detección de objetos y segmentación de imágenes debido a su capacidad para aprender jerarquías espaciales de características en datos estructurados en forma de cuadrícula y reducir el número de parámetros mediante el uso compartido de pesos.
> Además, funcionan mejor con datos que siguen el principio de localidad de características, según el cual es más probable que los datos vecinos (píxeles) estén relacionados que los píxeles distantes, lo que podría no darse en otros tipos de datos, como el texto.
> Asimismo, cabe señalar que las CNNs pueden identificar incluso características complejas, pero no pueden aplicar ningún contexto espacial, lo que significa que la misma característica encontrada en diferentes partes de la imagen será la misma.

### Ejemplo de definición de una CNN

*Aquí encontrarás una descripción de cómo definir una red neuronal convolucional (CNN) en PyTorch que comienza con un batch de imágenes RGB como dataset de tamaño 48x48 y utiliza capas convolucionales y maxpool para extraer características, seguidas de capas totalmente conectadas para la clasificación.*

Así es como se puede definir 1 capa convolucional en PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Número de canales de entrada. En el caso de imágenes RGB, este valor es 3 (uno por cada canal de color). Si se trabaja con imágenes en escala de grises, este valor sería 1.

- `out_channels`: Número de canales de salida (filtros) que aprenderá la capa convolucional. Este es un hiperparámetro que se puede ajustar según la arquitectura del modelo.

- `kernel_size`: Tamaño del filtro convolucional. Una opción habitual es 3x3, lo que significa que el filtro cubrirá un área de 3x3 de la imagen de entrada. Es como un sello de color de 3×3×3 que se utiliza para generar los out_channels a partir de los in_channels:
1. Coloca ese sello de 3×3×3 en la esquina superior izquierda del cubo de la imagen.
2. Multiplica cada peso por el píxel situado debajo, súmalos todos y añade el sesgo → obtienes un número.
3. Escribe ese número en un mapa vacío en la posición (0, 0).
4. Desliza el sello un píxel hacia la derecha (stride = 1) y repite hasta llenar una cuadrícula completa de 48×48.

- `padding`: Número de píxeles añadidos a cada lado de la entrada. El padding ayuda a conservar las dimensiones espaciales de la entrada, permitiendo un mayor control sobre el tamaño de salida. Por ejemplo, con un kernel de 3x3 y una entrada de 48x48 píxeles, un padding de 1 mantendrá el mismo tamaño de salida (48x48) después de la operación de convolución. Esto se debe a que el padding añade un borde de 1 píxel alrededor de la imagen de entrada, permitiendo que el kernel se deslice sobre los bordes sin reducir las dimensiones espaciales.

Por lo tanto, el número de parámetros entrenables en esta capa es:
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 parámetros entrenables.

Ten en cuenta que se añade un Bias (+1) por cada kernel utilizado, porque la función de cada capa convolucional es aprender una transformación lineal de la entrada, que se representa mediante la ecuación:
```plaintext
Y = f(W * X + b)
```
donde `W` es la matriz de pesos (los filtros aprendidos, 3x3x3 = 27 parámetros), `b` es el vector de sesgo, que es +1 para cada canal de salida.

Ten en cuenta que la salida de `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` será un tensor con forma `(batch_size, 32, 48, 48)`, porque 32 es el nuevo número de canales generados de 48x48 píxeles.

A continuación, podríamos conectar esta capa convolucional a otra capa convolucional, como: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Esto añadirá: (32x3x3 (tamaño del kernel) + 1 (sesgo)) x 64 (out_channels) = 18,496 parámetros entrenables y una salida con forma `(batch_size, 64, 48, 48)`.

Como puedes ver, el **número de parámetros crece rápidamente con cada capa convolucional adicional**, especialmente a medida que aumenta el número de canales de salida.

Una opción para controlar la cantidad de datos utilizados es usar **max pooling** después de cada capa convolucional. El max pooling reduce las dimensiones espaciales de los mapas de características, lo que ayuda a reducir el número de parámetros y la complejidad computacional, al tiempo que conserva las características importantes.

Se puede declarar como: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Básicamente, esto indica que se debe usar una cuadrícula de 2x2 píxeles y tomar el valor máximo de cada cuadrícula para reducir a la mitad el tamaño del mapa de características. Además, `stride=2` significa que la operación de pooling avanzará 2 píxeles cada vez, evitando en este caso cualquier solapamiento entre las regiones de pooling.

Con esta capa de pooling, la forma de salida después de la primera capa convolucional sería `(batch_size, 64, 24, 24)` tras aplicar `self.pool1` a la salida de `self.conv2`, reduciendo el tamaño a 1/4 del de la capa anterior.

> [!TIP]
> Es importante aplicar pooling después de las capas convolucionales para reducir las dimensiones espaciales de los mapas de características. Esto ayuda a controlar el número de parámetros y la complejidad computacional, a la vez que permite que el parámetro inicial aprenda características importantes.
>Puedes ver las convoluciones antes de una capa de pooling como una forma de extraer características de los datos de entrada (como líneas y bordes). Esta información seguirá presente en la salida agrupada, pero la siguiente capa convolucional no podrá ver los datos de entrada originales, sino únicamente la salida agrupada, que es una versión reducida de la capa anterior que conserva esa información.
>En el orden habitual: `Conv → ReLU → Pool`, cada ventana de pooling de 2×2 opera ahora sobre activaciones de características (“borde presente / no presente”), no sobre intensidades de píxeles sin procesar. Conservar la activación más fuerte realmente conserva la evidencia más relevante.

Después de añadir tantas capas convolucionales y de pooling como sean necesarias, podemos aplanar la salida para introducirla en capas fully connected. Esto se hace cambiando la forma del tensor a un vector 1D para cada muestra del batch:
```python
x = x.view(-1, 64*24*24)
```
Y con este vector 1D que contiene todos los parámetros de entrenamiento generados por las capas convolucionales y de pooling anteriores, podemos definir una capa totalmente conectada como:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Que tomará la salida aplanada de la capa anterior y la asignará a 512 unidades ocultas.

Observa cómo esta capa añadió `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` parámetros entrenables, lo que supone un aumento significativo en comparación con las capas convolucionales. Esto se debe a que las capas totalmente conectadas conectan cada neurona de una capa con cada neurona de la siguiente, lo que da lugar a un gran número de parámetros.

Finalmente, podemos añadir una capa de salida para producir los logits de clase finales:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Esto añadirá `(512 + 1 (bias)) * num_classes` parámetros entrenables, donde `num_classes` es el número de clases de la tarea de clasificación (p. ej., 43 para el dataset GTSRB).

Otra práctica común es añadir una capa de dropout antes de las capas fully connected para evitar el overfitting. Esto se puede hacer con:
```python
self.dropout = nn.Dropout(0.5)
```
Esta capa establece aleatoriamente una fracción de las unidades de entrada en cero durante el entrenamiento, lo que ayuda a evitar el sobreajuste al reducir la dependencia de neuronas específicas.

### Ejemplo de código de CNN
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
### Ejemplo de entrenamiento de código CNN

El siguiente código generará algunos datos de entrenamiento y entrenará el modelo `MY_NET` definido anteriormente. Algunos valores interesantes que conviene tener en cuenta:

- `EPOCHS` es el número de veces que el modelo verá el conjunto de datos completo durante el entrenamiento. Si EPOCH es demasiado pequeño, es posible que el modelo no aprenda lo suficiente; si es demasiado grande, podría producirse overfitting.
- `LEARNING_RATE` es el tamaño del paso del optimizador. Un learning rate pequeño puede provocar una convergencia lenta, mientras que uno grande podría sobrepasar la solución óptima e impedir la convergencia.
- `WEIGHT_DECAY` es un término de regularización que ayuda a evitar el overfitting penalizando los pesos grandes.

En cuanto al training loop, esta es información interesante que conviene conocer:
- `criterion = nn.CrossEntropyLoss()` es la función de pérdida utilizada para tareas de clasificación multiclase. Combina la activación softmax y la pérdida de entropía cruzada en una sola función, lo que la hace adecuada para entrenar modelos que generan class logits.
- Si se esperara que el modelo generase otros tipos de outputs, como clasificación binaria o regresión, utilizaríamos funciones de pérdida diferentes, como `nn.BCEWithLogitsLoss()` para clasificación binaria o `nn.MSELoss()` para regresión.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inicializa el optimizador Adam, que es una opción popular para entrenar modelos de deep learning. Adapta el learning rate de cada parámetro basándose en el primer y segundo momento de los gradientes.
- También podrían utilizarse otros optimizadores, como `optim.SGD` (Stochastic Gradient Descent) o `optim.RMSprop`, dependiendo de los requisitos específicos de la tarea de entrenamiento.
- El método `model.train()` establece el modelo en modo de entrenamiento, permitiendo que capas como dropout y batch normalization se comporten de forma diferente durante el entrenamiento que durante la evaluación.
- `optimizer.zero_grad()` borra los gradientes de todos los tensores optimizados antes del backward pass, lo cual es necesario porque los gradientes se acumulan de forma predeterminada en PyTorch. Si no se borrasen, los gradientes de iteraciones anteriores se sumarían a los gradientes actuales, provocando actualizaciones incorrectas.
- `loss.backward()` calcula los gradientes de la pérdida con respecto a los parámetros del modelo, que posteriormente utiliza el optimizador para actualizar los pesos.
- `optimizer.step()` actualiza los parámetros del modelo basándose en los gradientes calculados y el learning rate.
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
## Redes neuronales recurrentes (RNNs) <sup>[[3]](#references)</sup>

Las redes neuronales recurrentes (RNNs) son una clase de redes neuronales diseñadas para procesar datos secuenciales, como series temporales o lenguaje natural. A diferencia de las redes neuronales feedforward tradicionales, las RNNs tienen conexiones que vuelven sobre sí mismas, lo que les permite mantener un estado oculto que captura información sobre las entradas anteriores de la secuencia.

Los componentes principales de las RNNs incluyen:
- **Capas recurrentes**: Estas capas procesan las secuencias de entrada paso a paso, actualizando su estado oculto según la entrada actual y el estado oculto anterior. Esto permite a las RNNs aprender dependencias temporales en los datos.
- **Estado oculto**: El estado oculto es un vector que resume la información de los pasos temporales anteriores. Se actualiza en cada paso temporal y se utiliza para realizar predicciones para la entrada actual.
- **Capa de salida**: La capa de salida produce las predicciones finales basándose en el estado oculto. En muchos casos, las RNNs se utilizan para tareas como el modelado del lenguaje, donde la salida es una distribución de probabilidad sobre la siguiente palabra de una secuencia.

Por ejemplo, en un modelo de lenguaje, la RNN procesa una secuencia de palabras, por ejemplo, "The cat sat on the", y predice la siguiente palabra basándose en el contexto proporcionado por las palabras anteriores, en este caso, "mat".

### Memoria a largo y corto plazo (LSTM) y unidad recurrente con compuertas (GRU) <sup>[[3]](#references)</sup>

Las RNNs son especialmente eficaces para tareas que implican datos secuenciales, como el modelado del lenguaje, la traducción automática y el reconocimiento del habla. Sin embargo, pueden tener dificultades con **dependencias de largo alcance debido a problemas como la desaparición de gradientes**.

Para abordar esto, se desarrollaron arquitecturas especializadas como Long Short-Term Memory (LSTM) y Gated Recurrent Unit (GRU). Estas arquitecturas introducen mecanismos de compuertas que controlan el flujo de información, lo que les permite capturar dependencias de largo alcance de forma más eficaz.

- **LSTM**: Las redes LSTM utilizan tres compuertas (compuerta de entrada, compuerta de olvido y compuerta de salida) para regular el flujo de información hacia dentro y fuera del estado de la celda, lo que les permite recordar u olvidar información a lo largo de secuencias extensas. La compuerta de entrada controla cuánta información nueva se añade en función de la entrada y del estado oculto anterior; la compuerta de olvido controla cuánta información se descarta. Al combinar la compuerta de entrada y la compuerta de olvido obtenemos el nuevo estado. Finalmente, al combinar el nuevo estado de la celda con la entrada y el estado oculto anterior también obtenemos el nuevo estado oculto.
- **GRU**: Las redes GRU simplifican la arquitectura LSTM al combinar las compuertas de entrada y de olvido en una única compuerta de actualización, lo que las hace más eficientes computacionalmente y les permite seguir capturando dependencias de largo alcance.

## LLMs (modelos de lenguaje grandes)

Los modelos de lenguaje grandes (LLMs) son un tipo de modelo de deep learning diseñado específicamente para tareas de procesamiento del lenguaje natural. Se entrenan con enormes cantidades de datos de texto y pueden generar texto similar al humano, responder preguntas, traducir idiomas y realizar otras tareas relacionadas con el lenguaje.
Los LLMs suelen basarse en arquitecturas transformer, que utilizan mecanismos de self-attention para capturar las relaciones entre las palabras de una secuencia, lo que les permite comprender el contexto y generar texto coherente.

### Arquitectura Transformer <sup>[[4]](#references)</sup>
La arquitectura transformer es la base de muchos LLMs. Consta de una estructura encoder-decoder, donde el encoder procesa la secuencia de entrada y el decoder genera la secuencia de salida. Los componentes clave de la arquitectura transformer incluyen:
- **Mecanismo de Self-Attention**: Este mecanismo permite al modelo ponderar la importancia de las distintas palabras de una secuencia al generar representaciones. Calcula puntuaciones de atención basándose en las relaciones entre las palabras, lo que permite al modelo centrarse en el contexto relevante.
- **Atención Multi-Head**: Este componente permite al modelo capturar múltiples relaciones entre las palabras mediante el uso de múltiples attention heads, cada uno centrado en distintos aspectos de la entrada.
- **Codificación Posicional**: Dado que los transformers no tienen una noción integrada del orden de las palabras, se añade codificación posicional a los embeddings de entrada para proporcionar información sobre la posición de las palabras en la secuencia.

## Modelos de difusión <sup>[[5]](#references)</sup>
Los modelos de difusión son una clase de modelos generativos que aprenden a generar datos simulando un proceso de difusión. Son especialmente eficaces para tareas como la generación de imágenes y han ganado popularidad en los últimos años.
Los modelos de difusión funcionan transformando gradualmente una distribución simple de ruido en una distribución de datos compleja mediante una serie de pasos de difusión. Los componentes clave de los modelos de difusión incluyen:
- **Proceso de difusión hacia adelante**: Este proceso añade ruido gradualmente a los datos, transformándolos en una distribución simple de ruido. El proceso de difusión hacia adelante suele definirse mediante una serie de niveles de ruido, donde cada nivel corresponde a una cantidad específica de ruido añadida a los datos.
- **Proceso de difusión inverso**: Este proceso aprende a invertir el proceso de difusión hacia adelante, eliminando gradualmente el ruido de los datos para generar muestras de la distribución objetivo. El proceso de difusión inverso se entrena utilizando una función de pérdida que incentiva al modelo a reconstruir los datos originales a partir de muestras con ruido.

Además, para generar una imagen a partir de un prompt de texto, los modelos de difusión suelen seguir estos pasos:
1. **Codificación del texto**: El prompt de texto se codifica en una representación latente mediante un encoder de texto (por ejemplo, un modelo basado en transformer). Esta representación captura el significado semántico del texto.
2. **Muestreo de ruido**: Se muestrea un vector de ruido aleatorio a partir de una distribución gaussiana.
3. **Pasos de difusión**: El modelo aplica una serie de pasos de difusión, transformando gradualmente el vector de ruido en una imagen que corresponde al prompt de texto. Cada paso implica aplicar transformaciones aprendidas para eliminar el ruido de la imagen.

## References

- [1] [PyTorch - Tutorial de redes neuronales](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Modelos probabilísticos de difusión para eliminación de ruido](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
