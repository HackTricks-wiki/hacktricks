# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning

El aprendizaje profundo es un subconjunto del aprendizaje automático que utiliza redes neuronales con múltiples capas (redes neuronales profundas) para modelar patrones complejos en los datos. Ha logrado un éxito notable en varios dominios, incluyendo visión por computadora, procesamiento de lenguaje natural y reconocimiento de voz.

### Neural Networks

Las redes neuronales son los bloques de construcción del aprendizaje profundo. Consisten en nodos interconectados (neuronas) organizados en capas. Cada neurona recibe entradas, aplica una suma ponderada y pasa el resultado a través de una función de activación para producir una salida. Las capas se pueden categorizar de la siguiente manera:
- **Input Layer**: La primera capa que recibe los datos de entrada.
- **Hidden Layers**: Capas intermedias que realizan transformaciones en los datos de entrada. El número de capas ocultas y neuronas en cada capa puede variar, lo que lleva a diferentes arquitecturas.
- **Output Layer**: La capa final que produce la salida de la red, como probabilidades de clase en tareas de clasificación.

### Activation Functions

Cuando una capa de neuronas procesa datos de entrada, cada neurona aplica un peso y un sesgo a la entrada (`z = w * x + b`), donde `w` es el peso, `x` es la entrada y `b` es el sesgo. La salida de la neurona se pasa a través de una **función de activación para introducir no linealidad** en el modelo. Esta función de activación indica básicamente si la siguiente neurona "debería ser activada y cuánto". Esto permite que la red aprenda patrones y relaciones complejas en los datos, lo que le permite aproximar cualquier función continua.

Por lo tanto, las funciones de activación introducen no linealidad en la red neuronal, permitiéndole aprender relaciones complejas en los datos. Las funciones de activación comunes incluyen:
- **Sigmoid**: Mapea valores de entrada a un rango entre 0 y 1, a menudo utilizada en clasificación binaria.
- **ReLU (Rectified Linear Unit)**: Salida directa de la entrada si es positiva; de lo contrario, produce cero. Se utiliza ampliamente debido a su simplicidad y efectividad en el entrenamiento de redes profundas.
- **Tanh**: Mapea valores de entrada a un rango entre -1 y 1, a menudo utilizada en capas ocultas.
- **Softmax**: Convierte puntuaciones brutas en probabilidades, a menudo utilizada en la capa de salida para clasificación multiclase.

### Backpropagation

La retropropagación es el algoritmo utilizado para entrenar redes neuronales ajustando los pesos de las conexiones entre neuronas. Funciona calculando el gradiente de la función de pérdida con respecto a cada peso y actualizando los pesos en la dirección opuesta del gradiente para minimizar la pérdida. Los pasos involucrados en la retropropagación son:

1. **Forward Pass**: Calcular la salida de la red pasando la entrada a través de las capas y aplicando funciones de activación.
2. **Loss Calculation**: Calcular la pérdida (error) entre la salida predicha y el objetivo verdadero utilizando una función de pérdida (por ejemplo, error cuadrático medio para regresión, entropía cruzada para clasificación).
3. **Backward Pass**: Calcular los gradientes de la pérdida con respecto a cada peso utilizando la regla de la cadena del cálculo.
4. **Weight Update**: Actualizar los pesos utilizando un algoritmo de optimización (por ejemplo, descenso de gradiente estocástico, Adam) para minimizar la pérdida.

## Convolutional Neural Networks (CNNs)

Las Redes Neuronales Convolucionales (CNNs) son un tipo especializado de red neuronal diseñada para procesar datos en forma de cuadrícula, como imágenes. Son particularmente efectivas en tareas de visión por computadora debido a su capacidad para aprender automáticamente jerarquías espaciales de características.

Los componentes principales de las CNNs incluyen:
- **Convolutional Layers**: Aplican operaciones de convolución a los datos de entrada utilizando filtros (kernels) aprendibles para extraer características locales. Cada filtro se desliza sobre la entrada y calcula un producto punto, produciendo un mapa de características.
- **Pooling Layers**: Reducen las dimensiones espaciales de los mapas de características mientras retienen características importantes. Las operaciones de agrupamiento comunes incluyen max pooling y average pooling.
- **Fully Connected Layers**: Conectan cada neurona en una capa con cada neurona en la siguiente capa, similar a las redes neuronales tradicionales. Estas capas se utilizan típicamente al final de la red para tareas de clasificación.

Dentro de una CNN **`Convolutional Layers`**, también podemos distinguir entre:
- **Initial Convolutional Layer**: La primera capa convolucional que procesa los datos de entrada en bruto (por ejemplo, una imagen) y es útil para identificar características básicas como bordes y texturas.
- **Intermediate Convolutional Layers**: Capas convolucionales subsiguientes que se basan en las características aprendidas por la capa inicial, permitiendo que la red aprenda patrones y representaciones más complejas.
- **Final Convolutional Layer**: Las últimas capas convolucionales antes de las capas completamente conectadas, que capturan características de alto nivel y preparan los datos para la clasificación.

> [!TIP]
> Las CNNs son particularmente efectivas para tareas de clasificación de imágenes, detección de objetos y segmentación de imágenes debido a su capacidad para aprender jerarquías espaciales de características en datos en forma de cuadrícula y reducir el número de parámetros a través del uso compartido de pesos.
> Además, funcionan mejor con datos que apoyan el principio de localidad de características donde los datos vecinos (píxeles) son más propensos a estar relacionados que los píxeles distantes, lo que podría no ser el caso para otros tipos de datos como texto.
> Además, note cómo las CNNs podrán identificar incluso características complejas pero no podrán aplicar ningún contexto espacial, lo que significa que la misma característica encontrada en diferentes partes de la imagen será la misma.

### Example defining a CNN

*Aquí encontrará una descripción sobre cómo definir una Red Neuronal Convolucional (CNN) en PyTorch que comienza con un lote de imágenes RGB como conjunto de datos de tamaño 48x48 y utiliza capas convolucionales y maxpool para extraer características, seguidas de capas completamente conectadas para clasificación.*

Así es como puede definir 1 capa convolucional en PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Número de canales de entrada. En el caso de imágenes RGB, esto es 3 (uno para cada canal de color). Si está trabajando con imágenes en escala de grises, esto sería 1.

- `out_channels`: Número de canales de salida (filtros) que la capa convolucional aprenderá. Este es un hiperparámetro que puede ajustar según la arquitectura de su modelo.

- `kernel_size`: Tamaño del filtro de convolución. Una elección común es 3x3, lo que significa que el filtro cubrirá un área de 3x3 de la imagen de entrada. Esto es como un sello de color 3×3×3 que se utiliza para generar los out_channels a partir de los in_channels:
1. Coloque ese sello de 3×3×3 en la esquina superior izquierda del cubo de imagen.
2. Multiplique cada peso por el píxel debajo de él, súmelos todos, añada el sesgo → obtendrá un número.
3. Escriba ese número en un mapa en blanco en la posición (0, 0).
4. Deslice el sello un píxel a la derecha (stride = 1) y repita hasta llenar toda una cuadrícula de 48×48.

- `padding`: Número de píxeles añadidos a cada lado de la entrada. El padding ayuda a preservar las dimensiones espaciales de la entrada, permitiendo un mayor control sobre el tamaño de salida. Por ejemplo, con un kernel de 3x3 y una entrada de 48x48 píxeles, un padding de 1 mantendrá el tamaño de salida igual (48x48) después de la operación de convolución. Esto se debe a que el padding añade un borde de 1 píxel alrededor de la imagen de entrada, permitiendo que el kernel se deslice sobre los bordes sin reducir las dimensiones espaciales.

Luego, el número de parámetros entrenables en esta capa es:
- (3x3x3 (tamaño del kernel) + 1 (sesgo)) x 32 (out_channels) = 896 parámetros entrenables.

Tenga en cuenta que se añade un sesgo (+1) por cada kernel utilizado porque la función de cada capa convolucional es aprender una transformación lineal de la entrada, que se representa mediante la ecuación:
```plaintext
Y = f(W * X + b)
```
donde `W` es la matriz de pesos (los filtros aprendidos, 3x3x3 = 27 parámetros), `b` es el vector de sesgo que es +1 para cada canal de salida.

Tenga en cuenta que la salida de `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` será un tensor de forma `(batch_size, 32, 48, 48)`, porque 32 es el nuevo número de canales generados de tamaño 48x48 píxeles.

Luego, podríamos conectar esta capa convolucional a otra capa convolucional como: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Lo que añadirá: (32x3x3 (tamaño del kernel) + 1 (sesgo)) x 64 (canales de salida) = 18,496 parámetros entrenables y una salida de forma `(batch_size, 64, 48, 48)`.

Como puede ver, **el número de parámetros crece rápidamente con cada capa convolucional adicional**, especialmente a medida que aumenta el número de canales de salida.

Una opción para controlar la cantidad de datos utilizados es usar **max pooling** después de cada capa convolucional. Max pooling reduce las dimensiones espaciales de los mapas de características, lo que ayuda a reducir el número de parámetros y la complejidad computacional mientras se retienen características importantes.

Se puede declarar como: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Esto indica básicamente usar una cuadrícula de 2x2 píxeles y tomar el valor máximo de cada cuadrícula para reducir el tamaño del mapa de características a la mitad. Además, `stride=2` significa que la operación de pooling se moverá 2 píxeles a la vez, en este caso, evitando cualquier superposición entre las regiones de pooling.

Con esta capa de pooling, la forma de salida después de la primera capa convolucional sería `(batch_size, 64, 24, 24)` después de aplicar `self.pool1` a la salida de `self.conv2`, reduciendo el tamaño a 1/4 del de la capa anterior.

> [!TIP]
> Es importante hacer pooling después de las capas convolucionales para reducir las dimensiones espaciales de los mapas de características, lo que ayuda a controlar el número de parámetros y la complejidad computacional mientras se hace que el parámetro inicial aprenda características importantes.
> Puede ver las convoluciones antes de una capa de pooling como una forma de extraer características de los datos de entrada (como líneas, bordes), esta información seguirá presente en la salida agrupada, pero la siguiente capa convolucional no podrá ver los datos de entrada originales, solo la salida agrupada, que es una versión reducida de la capa anterior con esa información.
> En el orden habitual: `Conv → ReLU → Pool` cada ventana de pooling de 2×2 ahora compite con activaciones de características (“borde presente / no”), no con intensidades de píxeles en bruto. Mantener la activación más fuerte realmente conserva la evidencia más saliente.

Luego, después de agregar tantas capas convolucionales y de pooling como sea necesario, podemos aplanar la salida para alimentarla a capas completamente conectadas. Esto se hace reestructurando el tensor a un vector 1D para cada muestra en el lote:
```python
x = x.view(-1, 64*24*24)
```
Y con este vector 1D con todos los parámetros de entrenamiento generados por las capas convolucionales y de agrupamiento anteriores, podemos definir una capa completamente conectada como:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Que tomará la salida aplanada de la capa anterior y la mapeará a 512 unidades ocultas.

Nota cómo esta capa agregó `(64 * 24 * 24 + 1 (sesgo)) * 512 = 3,221,504` parámetros entrenables, lo que representa un aumento significativo en comparación con las capas convolucionales. Esto se debe a que las capas completamente conectadas conectan cada neurona en una capa con cada neurona en la siguiente capa, lo que lleva a un gran número de parámetros.

Finalmente, podemos agregar una capa de salida para producir los logits de clase finales:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Esto añadirá `(512 + 1 (sesgo)) * num_classes` parámetros entrenables, donde `num_classes` es el número de clases en la tarea de clasificación (por ejemplo, 43 para el conjunto de datos GTSRB).

Una última práctica común es agregar una capa de dropout antes de las capas completamente conectadas para prevenir el sobreajuste. Esto se puede hacer con:
```python
self.dropout = nn.Dropout(0.5)
```
Esta capa establece aleatoriamente una fracción de las unidades de entrada en cero durante el entrenamiento, lo que ayuda a prevenir el sobreajuste al reducir la dependencia de neuronas específicas.

### CNN Code example
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

El siguiente código generará algunos datos de entrenamiento y entrenará el modelo `MY_NET` definido arriba. Algunos valores interesantes a tener en cuenta:

- `EPOCHS` es el número de veces que el modelo verá todo el conjunto de datos durante el entrenamiento. Si EPOCH es demasiado pequeño, el modelo puede no aprender lo suficiente; si es demasiado grande, puede sobreajustarse.
- `LEARNING_RATE` es el tamaño del paso para el optimizador. Una tasa de aprendizaje pequeña puede llevar a una convergencia lenta, mientras que una grande puede sobrepasar la solución óptima y prevenir la convergencia.
- `WEIGHT_DECAY` es un término de regularización que ayuda a prevenir el sobreajuste penalizando pesos grandes.

Respecto al bucle de entrenamiento, esta es información interesante a saber:
- La `criterion = nn.CrossEntropyLoss()` es la función de pérdida utilizada para tareas de clasificación multiclase. Combina la activación softmax y la pérdida de entropía cruzada en una sola función, lo que la hace adecuada para entrenar modelos que producen logits de clase.
- Si se esperaba que el modelo produjera otros tipos de salidas, como clasificación binaria o regresión, usaríamos diferentes funciones de pérdida como `nn.BCEWithLogitsLoss()` para clasificación binaria o `nn.MSELoss()` para regresión.
- El `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inicializa el optimizador Adam, que es una opción popular para entrenar modelos de aprendizaje profundo. Se adapta la tasa de aprendizaje para cada parámetro en función de los primeros y segundos momentos de los gradientes.
- Otros optimizadores como `optim.SGD` (Descenso de Gradiente Estocástico) o `optim.RMSprop` también podrían usarse, dependiendo de los requisitos específicos de la tarea de entrenamiento.
- El método `model.train()` establece el modelo en modo de entrenamiento, permitiendo que capas como dropout y normalización por lotes se comporten de manera diferente durante el entrenamiento en comparación con la evaluación.
- `optimizer.zero_grad()` limpia los gradientes de todos los tensores optimizados antes de la pasada hacia atrás, lo cual es necesario porque los gradientes se acumulan por defecto en PyTorch. Si no se limpian, los gradientes de iteraciones anteriores se sumarían a los gradientes actuales, llevando a actualizaciones incorrectas.
- `loss.backward()` calcula los gradientes de la pérdida con respecto a los parámetros del modelo, que luego son utilizados por el optimizador para actualizar los pesos.
- `optimizer.step()` actualiza los parámetros del modelo en función de los gradientes calculados y la tasa de aprendizaje.
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
## Redes Neuronales Recurrentes (RNNs)

Las Redes Neuronales Recurrentes (RNNs) son una clase de redes neuronales diseñadas para procesar datos secuenciales, como series temporales o lenguaje natural. A diferencia de las redes neuronales tradicionales de avance, las RNNs tienen conexiones que se retroalimentan, lo que les permite mantener un estado oculto que captura información sobre entradas anteriores en la secuencia.

Los componentes principales de las RNNs incluyen:
- **Capas Recurrentes**: Estas capas procesan secuencias de entrada un paso de tiempo a la vez, actualizando su estado oculto en función de la entrada actual y el estado oculto anterior. Esto permite que las RNNs aprendan dependencias temporales en los datos.
- **Estado Oculto**: El estado oculto es un vector que resume la información de pasos de tiempo anteriores. Se actualiza en cada paso de tiempo y se utiliza para hacer predicciones sobre la entrada actual.
- **Capa de Salida**: La capa de salida produce las predicciones finales basadas en el estado oculto. En muchos casos, las RNNs se utilizan para tareas como modelado de lenguaje, donde la salida es una distribución de probabilidad sobre la siguiente palabra en una secuencia.

Por ejemplo, en un modelo de lenguaje, la RNN procesa una secuencia de palabras, por ejemplo, "El gato se sentó en el" y predice la siguiente palabra en función del contexto proporcionado por las palabras anteriores, en este caso, "tapete".

### Memoria a Largo y Corto Plazo (LSTM) y Unidad Recurrente Con Puertas (GRU)

Las RNNs son particularmente efectivas para tareas que involucran datos secuenciales, como modelado de lenguaje, traducción automática y reconocimiento de voz. Sin embargo, pueden tener dificultades con **dependencias a largo plazo debido a problemas como el desvanecimiento de gradientes**.

Para abordar esto, se desarrollaron arquitecturas especializadas como Memoria a Largo y Corto Plazo (LSTM) y Unidad Recurrente Con Puertas (GRU). Estas arquitecturas introducen mecanismos de puertas que controlan el flujo de información, permitiéndoles capturar dependencias a largo plazo de manera más efectiva.

- **LSTM**: Las redes LSTM utilizan tres puertas (puerta de entrada, puerta de olvido y puerta de salida) para regular el flujo de información dentro y fuera del estado de la celda, lo que les permite recordar o olvidar información a lo largo de secuencias largas. La puerta de entrada controla cuánto nueva información agregar en función de la entrada y el estado oculto anterior, la puerta de olvido controla cuánto información descartar. Combinando la puerta de entrada y la puerta de olvido obtenemos el nuevo estado. Finalmente, combinando el nuevo estado de la celda, con la entrada y el estado oculto anterior también obtenemos el nuevo estado oculto.
- **GRU**: Las redes GRU simplifican la arquitectura LSTM al combinar las puertas de entrada y olvido en una única puerta de actualización, haciéndolas computacionalmente más eficientes mientras aún capturan dependencias a largo plazo.

## LLMs (Modelos de Lenguaje Grande)

Los Modelos de Lenguaje Grande (LLMs) son un tipo de modelo de aprendizaje profundo diseñado específicamente para tareas de procesamiento de lenguaje natural. Se entrenan con grandes cantidades de datos textuales y pueden generar texto similar al humano, responder preguntas, traducir idiomas y realizar diversas otras tareas relacionadas con el lenguaje. 
Los LLMs se basan típicamente en arquitecturas de transformadores, que utilizan mecanismos de autoatención para capturar relaciones entre palabras en una secuencia, lo que les permite entender el contexto y generar texto coherente.

### Arquitectura de Transformador
La arquitectura de transformador es la base de muchos LLMs. Consiste en una estructura de codificador-decodificador, donde el codificador procesa la secuencia de entrada y el decodificador genera la secuencia de salida. Los componentes clave de la arquitectura de transformador incluyen:
- **Mecanismo de Autoatención**: Este mecanismo permite al modelo ponderar la importancia de diferentes palabras en una secuencia al generar representaciones. Calcula puntajes de atención basados en las relaciones entre palabras, lo que permite al modelo centrarse en el contexto relevante.
- **Atención Multi-Cabeza**: Este componente permite al modelo capturar múltiples relaciones entre palabras utilizando múltiples cabezas de atención, cada una enfocándose en diferentes aspectos de la entrada.
- **Codificación Posicional**: Dado que los transformadores no tienen una noción incorporada del orden de las palabras, se agrega codificación posicional a las incrustaciones de entrada para proporcionar información sobre la posición de las palabras en la secuencia.

## Modelos de Difusión
Los modelos de difusión son una clase de modelos generativos que aprenden a generar datos simulando un proceso de difusión. Son particularmente efectivos para tareas como la generación de imágenes y han ganado popularidad en los últimos años. 
Los modelos de difusión funcionan transformando gradualmente una distribución de ruido simple en una distribución de datos compleja a través de una serie de pasos de difusión. Los componentes clave de los modelos de difusión incluyen:
- **Proceso de Difusión Adelante**: Este proceso agrega gradualmente ruido a los datos, transformándolos en una distribución de ruido simple. El proceso de difusión hacia adelante se define típicamente por una serie de niveles de ruido, donde cada nivel corresponde a una cantidad específica de ruido agregado a los datos.
- **Proceso de Difusión Inversa**: Este proceso aprende a revertir el proceso de difusión hacia adelante, desruido gradualmente los datos para generar muestras de la distribución objetivo. El proceso de difusión inversa se entrena utilizando una función de pérdida que alienta al modelo a reconstruir los datos originales a partir de muestras ruidosas.

Además, para generar una imagen a partir de un aviso de texto, los modelos de difusión típicamente siguen estos pasos:
1. **Codificación de Texto**: El aviso de texto se codifica en una representación latente utilizando un codificador de texto (por ejemplo, un modelo basado en transformadores). Esta representación captura el significado semántico del texto.
2. **Muestreo de Ruido**: Se muestrea un vector de ruido aleatorio de una distribución gaussiana.
3. **Pasos de Difusión**: El modelo aplica una serie de pasos de difusión, transformando gradualmente el vector de ruido en una imagen que corresponde al aviso de texto. Cada paso implica aplicar transformaciones aprendidas para desruido la imagen.

{{#include ../banners/hacktricks-training.md}}
