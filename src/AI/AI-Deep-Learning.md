# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning <sup>[[1]](#references)</sup>

Deep Learning ist eine Teilmenge des Machine Learning, die neuronale Netze mit mehreren Schichten (tiefe neuronale Netze) verwendet, um komplexe Muster in Daten zu modellieren. Es hat in verschiedenen Bereichen bemerkenswerte Erfolge erzielt, darunter Computer Vision, Natural Language Processing und Spracherkennung.

### Neuronale Netze

Neuronale Netze sind die Bausteine des Deep Learning. Sie bestehen aus miteinander verbundenen Knoten (Neuronen), die in Schichten organisiert sind. Jedes Neuron empfängt Eingaben, wendet eine gewichtete Summe an und leitet das Ergebnis durch eine Aktivierungsfunktion, um eine Ausgabe zu erzeugen. Die Schichten lassen sich wie folgt kategorisieren:
- **Eingabeschicht**: Die erste Schicht, die die Eingabedaten empfängt.
- **Verborgene Schichten**: Zwischenschichten, die Transformationen an den Eingabedaten durchführen. Die Anzahl der verborgenen Schichten und Neuronen in jeder Schicht kann variieren, was zu unterschiedlichen Architekturen führt.
- **Ausgabeschicht**: Die letzte Schicht, die die Ausgabe des Netzes erzeugt, beispielsweise Klassenwahrscheinlichkeiten bei Klassifizierungsaufgaben.


### Aktivierungsfunktionen

Wenn eine Schicht aus Neuronen Eingabedaten verarbeitet, wendet jedes Neuron ein Gewicht und einen Bias auf die Eingabe an (`z = w * x + b`), wobei `w` das Gewicht, `x` die Eingabe und `b` der Bias ist. Die Ausgabe des Neurons wird anschließend durch eine **Aktivierungsfunktion geleitet, um Nichtlinearität** in das Modell einzuführen. Diese Aktivierungsfunktion gibt im Grunde an, ob das nächste Neuron „aktiviert werden sollte und in welchem Maß“. Dadurch kann das Netz komplexe Muster und Beziehungen in den Daten lernen und jede kontinuierliche Funktion approximieren.

Aktivierungsfunktionen führen daher Nichtlinearität in das neuronale Netz ein und ermöglichen es ihm, komplexe Beziehungen in den Daten zu lernen. Zu den gängigen Aktivierungsfunktionen gehören:
- **Sigmoid**: Ordnet Eingabewerte einem Bereich zwischen 0 und 1 zu und wird häufig bei binärer Klassifizierung verwendet.
- **ReLU (Rectified Linear Unit)**: Gibt die Eingabe direkt aus, wenn sie positiv ist; andernfalls gibt sie null aus. Sie wird aufgrund ihrer Einfachheit und Effektivität beim Training tiefer Netze häufig verwendet.
- **Tanh**: Ordnet Eingabewerte einem Bereich zwischen -1 und 1 zu und wird häufig in verborgenen Schichten verwendet.
- **Softmax**: Wandelt Rohwerte in Wahrscheinlichkeiten um und wird häufig in der Ausgabeschicht für die Klassifizierung mehrerer Klassen verwendet.

### Backpropagation

Backpropagation ist der Algorithmus, der zum Trainieren neuronaler Netze verwendet wird, indem die Gewichte der Verbindungen zwischen den Neuronen angepasst werden. Dabei wird der Gradient der Verlustfunktion bezüglich jedes Gewichts berechnet und die Gewichte in die entgegengesetzte Richtung des Gradienten aktualisiert, um den Verlust zu minimieren. Die Schritte der Backpropagation sind:

1. **Forward Pass**: Berechne die Ausgabe des Netzes, indem die Eingabe durch die Schichten geleitet und Aktivierungsfunktionen angewendet werden.
2. **Verlustberechnung**: Berechne den Verlust (Fehler) zwischen der vorhergesagten Ausgabe und dem tatsächlichen Ziel mithilfe einer Verlustfunktion (z. B. mittlerer quadratischer Fehler bei Regression oder Cross-Entropy bei Klassifizierung).
3. **Backward Pass**: Berechne mithilfe der Kettenregel der Differentialrechnung die Gradienten des Verlusts bezüglich jedes Gewichts.
4. **Gewichtsaktualisierung**: Aktualisiere die Gewichte mithilfe eines Optimierungsalgorithmus (z. B. Stochastic Gradient Descent oder Adam), um den Verlust zu minimieren.

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Convolutional Neural Networks (CNNs) sind ein spezialisierter Typ neuronaler Netze, der für die Verarbeitung gitterartiger Daten wie Bildern entwickelt wurde. Sie sind bei Computer-Vision-Aufgaben besonders effektiv, da sie räumliche Hierarchien von Merkmalen automatisch erlernen können.

Die Hauptkomponenten von CNNs umfassen:
- **Convolutional Layers**: Wenden mithilfe erlernbarer Filter (Kernels) Faltungsoperationen auf die Eingabedaten an, um lokale Merkmale zu extrahieren. Jeder Filter gleitet über die Eingabe und berechnet ein Skalarprodukt, wodurch eine Feature Map entsteht.
- **Pooling Layers**: Verkleinern die Feature Maps, um ihre räumlichen Dimensionen zu reduzieren und dabei wichtige Merkmale beizubehalten. Zu den gängigen Pooling-Operationen gehören Max Pooling und Average Pooling.
- **Fully Connected Layers**: Verbinden jedes Neuron einer Schicht mit jedem Neuron der nächsten Schicht, ähnlich wie bei herkömmlichen neuronalen Netzen. Diese Schichten werden typischerweise am Ende des Netzes für Klassifizierungsaufgaben verwendet.

Innerhalb der **`Convolutional Layers`** eines CNNs kann außerdem unterschieden werden zwischen:
- **Initial Convolutional Layer**: Die erste Convolutional Layer, die die rohen Eingabedaten (z. B. ein Bild) verarbeitet und hilfreich ist, um grundlegende Merkmale wie Kanten und Texturen zu identifizieren.
- **Intermediate Convolutional Layers**: Nachfolgende Convolutional Layers, die auf den von der anfänglichen Schicht erlernten Merkmalen aufbauen und es dem Netz ermöglichen, komplexere Muster und Repräsentationen zu lernen.
- **Final Convolutional Layer**: Die letzten Convolutional Layers vor den Fully Connected Layers, die Merkmale auf hoher Abstraktionsebene erfassen und die Daten für die Klassifizierung vorbereiten.

> [!TIP]
> CNNs sind aufgrund ihrer Fähigkeit, räumliche Hierarchien von Merkmalen in gitterartigen Daten zu lernen und durch Weight Sharing die Anzahl der Parameter zu reduzieren, besonders effektiv für Bildklassifizierung, Objekterkennung und Bildsegmentierungsaufgaben.
> Darüber hinaus funktionieren sie besser mit Daten, die das Prinzip der Merkmalslokalität unterstützen, bei dem benachbarte Daten (Pixel) mit größerer Wahrscheinlichkeit miteinander zusammenhängen als weit entfernte Pixel, was bei anderen Datentypen wie Text möglicherweise nicht der Fall ist.
> Außerdem ist zu beachten, dass CNNs auch komplexe Merkmale identifizieren können, aber keinen räumlichen Kontext anwenden können. Das bedeutet, dass dasselbe Merkmal, das an verschiedenen Stellen des Bildes gefunden wird, identisch behandelt wird.

### Beispiel für die Definition eines CNNs

*Hier findest du eine Beschreibung, wie man in PyTorch ein Convolutional Neural Network (CNN) definiert, das mit einem Datensatz aus RGB-Bildern der Größe 48x48 beginnt und Convolutional Layers sowie Maxpool verwendet, um Merkmale zu extrahieren, gefolgt von Fully Connected Layers zur Klassifizierung.*

So kann man in PyTorch 1 Convolutional Layer definieren: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Anzahl der Eingabekanäle. Bei RGB-Bildern ist dieser Wert 3 (einer für jeden Farbkanal). Wenn du mit Graustufenbildern arbeitest, ist der Wert 1.

- `out_channels`: Anzahl der Ausgabekanäle (Filter), die die Convolutional Layer lernen wird. Dies ist ein Hyperparameter, den du abhängig von der Architektur deines Modells anpassen kannst.

- `kernel_size`: Größe des Convolutional Filters. Eine häufige Wahl ist 3x3, was bedeutet, dass der Filter einen 3x3-Bereich des Eingabebildes abdeckt. Dies entspricht einem 3×3×3-Farbstempel, der verwendet wird, um die `out_channels` aus den `in_channels` zu erzeugen:
1. Platziere den 3×3×3-Stempel in der oberen linken Ecke des Bildwürfels.
2. Multipliziere jedes Gewicht mit dem darunterliegenden Pixel, addiere alle Ergebnisse und addiere den Bias → du erhältst eine Zahl.
3. Schreibe diese Zahl an Position (0, 0) in eine leere Map.
4. Verschiebe den Stempel um ein Pixel nach rechts (Stride = 1) und wiederhole den Vorgang, bis du ein vollständiges 48×48-Raster gefüllt hast.

- `padding`: Anzahl der Pixel, die jeder Seite der Eingabe hinzugefügt werden. Padding hilft dabei, die räumlichen Dimensionen der Eingabe zu erhalten, und ermöglicht eine bessere Kontrolle über die Ausgabegröße. Bei einem 3x3-Kernel und einer 48x48-Pixel-Eingabe bewirkt ein Padding von 1 beispielsweise, dass die Ausgabe nach der Faltungsoperation dieselbe Größe (48x48) behält. Der Grund dafür ist, dass das Padding einen Rand von 1 Pixeln um das Eingabebild hinzufügt, sodass der Kernel über die Ränder gleiten kann, ohne die räumlichen Dimensionen zu verringern.

Die Anzahl der trainierbaren Parameter in dieser Schicht beträgt dann:
- (3x3x3 (Kernelgröße) + 1 (Bias)) x 32 (out_channels) = 896 trainierbare Parameter.

Beachte, dass pro verwendetem Kernel ein Bias (+1) hinzugefügt wird, da die Funktion jeder Convolutional Layer darin besteht, eine lineare Transformation der Eingabe zu lernen, die durch folgende Gleichung dargestellt wird:
```plaintext
Y = f(W * X + b)
```
wobei `W` die Gewichtsmatrix (die gelernten Filter, 3x3x3 = 27 Parameter) und `b` der Bias-Vektor ist, der für jeden Ausgabekanal +1 beträgt.

Beachte, dass die Ausgabe von `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` ein Tensor der Form `(batch_size, 32, 48, 48)` sein wird, da 32 die neue Anzahl der generierten Kanäle mit einer Größe von 48x48 Pixeln ist.

Anschließend könnten wir diese convolutional layer mit einer weiteren convolutional layer verbinden, etwa so: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Dadurch kommen hinzu: (32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 trainierbare Parameter sowie eine Ausgabe der Form `(batch_size, 64, 48, 48)`.

Wie du sehen kannst, **wächst die Anzahl der Parameter mit jeder zusätzlichen convolutional layer schnell**, insbesondere wenn die Anzahl der output channels steigt.

Eine Möglichkeit, die Menge der verwendeten Daten zu kontrollieren, besteht darin, nach jeder convolutional layer **max pooling** zu verwenden. Max pooling reduziert die räumlichen Dimensionen der feature maps. Dadurch werden die Anzahl der Parameter und die computational complexity verringert, während wichtige Features erhalten bleiben.

Dies kann folgendermaßen deklariert werden: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Dies bedeutet im Grunde, dass ein Raster aus 2x2 Pixeln verwendet und der Maximalwert aus jedem Raster übernommen wird, um die Größe der feature map zu halbieren. Außerdem bedeutet `stride=2`, dass sich die pooling operation jeweils um 2 Pixel bewegt, wodurch in diesem Fall eine Überlappung zwischen den pooling regions verhindert wird.

Mit dieser pooling layer hätte die Ausgabeform nach der ersten convolutional layer `(batch_size, 64, 24, 24)`, nachdem `self.pool1` auf die Ausgabe von `self.conv2` angewendet wurde und die Größe auf ein Viertel der vorherigen layer reduziert wurde.

> [!TIP]
> Es ist wichtig, nach den convolutional layers pooling anzuwenden, um die räumlichen Dimensionen der feature maps zu reduzieren. Dadurch lassen sich die Anzahl der Parameter und die computational complexity kontrollieren, während die initialen Parameter wichtige Features lernen.
>Du kannst die convolutions vor einer pooling layer als eine Möglichkeit betrachten, Features aus den Eingabedaten zu extrahieren (etwa Linien und Kanten). Diese Informationen sind weiterhin in der gepoolten Ausgabe enthalten, aber die nächste convolutional layer kann die ursprünglichen Eingabedaten nicht sehen, sondern nur die gepoolte Ausgabe, die eine reduzierte Version der vorherigen layer mit diesen Informationen ist.
>In der üblichen Reihenfolge `Conv → ReLU → Pool` arbeitet jedes 2×2-pooling window nun mit feature activations („Kante vorhanden / nicht vorhanden“) und nicht mit rohen Pixelintensitäten. Das Beibehalten der stärksten activation erhält tatsächlich die aussagekräftigsten Hinweise.

Nachdem wir so viele convolutional und pooling layers hinzugefügt haben wie nötig, können wir die Ausgabe flatten, um sie in fully connected layers einzuspeisen. Dazu wird der Tensor für jedes Sample im Batch in einen 1D-Vektor umgeformt:
```python
x = x.view(-1, 64*24*24)
```
Und mit diesem 1D-Vektor mit allen von den vorherigen Convolutional- und Pooling-Layern generierten Trainingsparametern können wir eine Fully-Connected-Layer wie folgt definieren:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Das nimmt die abgeflachte Ausgabe der vorherigen Schicht und ordnet sie 512 Hidden Units zu.

Beachte, dass diese Schicht `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` trainierbare Parameter hinzugefügt hat, was im Vergleich zu den Convolutional Layers eine erhebliche Zunahme darstellt. Das liegt daran, dass Fully Connected Layers jedes Neuron in einer Schicht mit jedem Neuron in der nächsten Schicht verbinden, wodurch eine große Anzahl an Parametern entsteht.

Schließlich können wir eine Ausgabeschicht hinzufügen, um die finalen Klassen-Logits zu erzeugen:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Dies fügt `(512 + 1 (bias)) * num_classes` trainierbare Parameter hinzu, wobei `num_classes` die Anzahl der Klassen in der Klassifizierungsaufgabe ist (z. B. 43 für den GTSRB-Datensatz).

Eine weitere gängige Praxis besteht darin, vor den fully connected layers eine dropout layer hinzuzufügen, um Overfitting zu verhindern. Dies kann folgendermaßen erfolgen:
```python
self.dropout = nn.Dropout(0.5)
```
Diese Schicht setzt während des Trainings zufällig einen Teil der Eingabeeinheiten auf null. Dadurch wird Overfitting verhindert, indem die Abhängigkeit von bestimmten Neuronen reduziert wird.

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
### CNN-Code-Trainingsbeispiel

Der folgende Code erstellt einige Trainingsdaten und trainiert das oben definierte Modell `MY_NET`. Einige interessante Werte, die man beachten sollte:

- `EPOCHS` ist die Anzahl der Durchläufe, in denen das Modell während des Trainings den gesamten Datensatz sieht. Wenn EPOCH zu klein ist, lernt das Modell möglicherweise nicht genug; wenn sie zu groß ist, kann es zu Overfitting kommen.
- `LEARNING_RATE` ist die Schrittgröße des Optimizers. Eine kleine Learning Rate kann zu langsamer Konvergenz führen, während eine große den optimalen Lösungsbereich überspringen und die Konvergenz verhindern kann.
- `WEIGHT_DECAY` ist ein Regularisierungsterm, der hilft, Overfitting zu verhindern, indem große Gewichte bestraft werden.

Zum Training Loop gibt es einige interessante Informationen:
- `criterion = nn.CrossEntropyLoss()` ist die Loss-Funktion für Multi-Class-Classification-Aufgaben. Sie kombiniert Softmax-Aktivierung und Cross-Entropy-Loss in einer einzigen Funktion und eignet sich daher zum Trainieren von Modellen, die Class-Logits ausgeben.
- Wenn das Modell andere Arten von Outputs ausgeben soll, etwa für Binary Classification oder Regression, würden wir andere Loss-Funktionen verwenden, beispielsweise `nn.BCEWithLogitsLoss()` für Binary Classification oder `nn.MSELoss()` für Regression.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` initialisiert den Adam-Optimizer, der häufig zum Trainieren von Deep-Learning-Modellen verwendet wird. Er passt die Learning Rate für jeden Parameter basierend auf dem ersten und zweiten Moment der Gradienten an.
- Abhängig von den spezifischen Anforderungen der Trainingsaufgabe könnten auch andere Optimizer wie `optim.SGD` (Stochastic Gradient Descent) oder `optim.RMSprop` verwendet werden.
- Die Methode `model.train()` versetzt das Modell in den Trainingsmodus, sodass sich Layer wie Dropout und Batch Normalization während des Trainings anders verhalten als bei der Evaluation.
- `optimizer.zero_grad()` löscht vor dem Backward Pass die Gradienten aller optimierten Tensoren. Dies ist erforderlich, weil sich Gradienten in PyTorch standardmäßig akkumulieren. Wenn sie nicht gelöscht werden, würden die Gradienten vorheriger Iterationen zu den aktuellen Gradienten addiert, was zu falschen Updates führen würde.
- `loss.backward()` berechnet die Gradienten des Loss bezüglich der Modellparameter. Diese werden anschließend vom Optimizer verwendet, um die Gewichte zu aktualisieren.
- `optimizer.step()` aktualisiert die Modellparameter basierend auf den berechneten Gradienten und der Learning Rate.
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
## Rekurrente neuronale Netze (RNNs) <sup>[[3]](#references)</sup>

Rekurrente neuronale Netze (RNNs) sind eine Klasse neuronaler Netze, die für die Verarbeitung sequenzieller Daten wie Zeitreihen oder natürlicher Sprache entwickelt wurden. Im Gegensatz zu herkömmlichen Feedforward-neuronalen Netzen verfügen RNNs über Verbindungen, die auf sich selbst zurückführen. Dadurch können sie einen verborgenen Zustand aufrechterhalten, der Informationen über vorherige Eingaben in der Sequenz erfasst.

Die wichtigsten Komponenten von RNNs umfassen:
- **Rekurrente Schichten**: Diese Schichten verarbeiten Eingabesequenzen jeweils einen Zeitschritt nach dem anderen und aktualisieren ihren verborgenen Zustand basierend auf der aktuellen Eingabe und dem vorherigen verborgenen Zustand. Dadurch können RNNs zeitliche Abhängigkeiten in den Daten erlernen.
- **Verborgener Zustand**: Der verborgene Zustand ist ein Vektor, der die Informationen aus vorherigen Zeitschritten zusammenfasst. Er wird bei jedem Zeitschritt aktualisiert und verwendet, um Vorhersagen für die aktuelle Eingabe zu treffen.
- **Ausgabeschicht**: Die Ausgabeschicht erzeugt die endgültigen Vorhersagen basierend auf dem verborgenen Zustand. In vielen Fällen werden RNNs für Aufgaben wie Language Modeling verwendet, bei denen die Ausgabe eine Wahrscheinlichkeitsverteilung über das nächste Wort in einer Sequenz ist.

In einem Language Model verarbeitet das RNN beispielsweise eine Sequenz von Wörtern, etwa „The cat sat on the“, und sagt basierend auf dem durch die vorherigen Wörter bereitgestellten Kontext das nächste Wort voraus, in diesem Fall „mat“.

### Long Short-Term Memory (LSTM) und Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

RNNs sind besonders effektiv für Aufgaben mit sequenziellen Daten, etwa Language Modeling, maschinelle Übersetzung und Spracherkennung. Allerdings können sie aufgrund von Problemen wie **verschwindenden Gradienten Schwierigkeiten mit weitreichenden Abhängigkeiten haben**.

Um diesem Problem zu begegnen, wurden spezialisierte Architekturen wie Long Short-Term Memory (LSTM) und Gated Recurrent Unit (GRU) entwickelt. Diese Architekturen führen Gate-Mechanismen ein, die den Informationsfluss steuern und es ihnen ermöglichen, weitreichende Abhängigkeiten effektiver zu erfassen.

- **LSTM**: LSTM-Netze verwenden drei Gates (Input-Gate, Forget-Gate und Output-Gate), um den Informationsfluss in den Zellzustand und aus ihm heraus zu regulieren. Dadurch können sie sich über lange Sequenzen hinweg an Informationen erinnern oder diese vergessen. Das Input-Gate steuert, wie viele neue Informationen basierend auf der Eingabe und dem vorherigen verborgenen Zustand hinzugefügt werden, während das Forget-Gate steuert, wie viele Informationen verworfen werden. Durch die Kombination des Input-Gates und des Forget-Gates erhalten wir den neuen Zustand. Durch die Kombination des neuen Zellzustands mit der Eingabe und dem vorherigen verborgenen Zustand erhalten wir schließlich auch den neuen verborgenen Zustand.
- **GRU**: GRU-Netze vereinfachen die LSTM-Architektur, indem sie das Input-Gate und das Forget-Gate zu einem einzelnen Update-Gate kombinieren. Dadurch sind sie rechnerisch effizienter und können dennoch weitreichende Abhängigkeiten erfassen.

## LLMs (Large Language Models)

Large Language Models (LLMs) sind eine Art von Deep-Learning-Modellen, die speziell für Aufgaben der Verarbeitung natürlicher Sprache entwickelt wurden. Sie werden mit riesigen Mengen an Textdaten trainiert und können menschenähnlichen Text erzeugen, Fragen beantworten, Sprachen übersetzen und verschiedene andere sprachbezogene Aufgaben ausführen.
LLMs basieren typischerweise auf Transformer-Architekturen, die Self-Attention-Mechanismen verwenden, um Beziehungen zwischen Wörtern in einer Sequenz zu erfassen. Dadurch können sie Kontext verstehen und kohärenten Text erzeugen.

### Transformer-Architektur <sup>[[4]](#references)</sup>
Die Transformer-Architektur bildet die Grundlage vieler LLMs. Sie besteht aus einer Encoder-Decoder-Struktur, bei der der Encoder die Eingabesequenz verarbeitet und der Decoder die Ausgabesequenz erzeugt. Zu den wichtigsten Komponenten der Transformer-Architektur gehören:
- **Self-Attention-Mechanismus**: Dieser Mechanismus ermöglicht es dem Modell, bei der Erstellung von Repräsentationen die Wichtigkeit verschiedener Wörter in einer Sequenz zu gewichten. Er berechnet Attention-Scores basierend auf den Beziehungen zwischen Wörtern, sodass sich das Modell auf relevanten Kontext konzentrieren kann.
- **Multi-Head-Attention**: Diese Komponente ermöglicht es dem Modell, mehrere Beziehungen zwischen Wörtern zu erfassen, indem mehrere Attention-Heads verwendet werden, die sich jeweils auf unterschiedliche Aspekte der Eingabe konzentrieren.
- **Positionskodierung**: Da Transformer kein integriertes Verständnis der Wortreihenfolge besitzen, wird den Input-Embeddings eine Positionskodierung hinzugefügt, um Informationen über die Position der Wörter in der Sequenz bereitzustellen.

## Diffusionsmodelle <sup>[[5]](#references)</sup>
Diffusionsmodelle sind eine Klasse generativer Modelle, die lernen, Daten zu erzeugen, indem sie einen Diffusionsprozess simulieren. Sie sind besonders effektiv für Aufgaben wie die Bilderzeugung und haben in den letzten Jahren an Popularität gewonnen.
Diffusionsmodelle funktionieren, indem sie eine einfache Rauschverteilung durch eine Reihe von Diffusionsschritten schrittweise in eine komplexe Datenverteilung transformieren. Zu den wichtigsten Komponenten von Diffusionsmodellen gehören:
- **Vorwärtsdiffusionsprozess**: Dieser Prozess fügt den Daten schrittweise Rauschen hinzu und transformiert sie in eine einfache Rauschverteilung. Der Vorwärtsdiffusionsprozess wird typischerweise durch eine Reihe von Rauschpegeln definiert, wobei jeder Pegel einer bestimmten Menge an Rauschen entspricht, die den Daten hinzugefügt wird.
- **Rückwärtsdiffusionsprozess**: Dieser Prozess lernt, den Vorwärtsdiffusionsprozess umzukehren, indem er die Daten schrittweise entrauscht, um Samples aus der Zielverteilung zu erzeugen. Der Rückwärtsdiffusionsprozess wird mithilfe einer Loss-Funktion trainiert, die das Modell dazu anhält, die ursprünglichen Daten aus verrauschten Samples zu rekonstruieren.

Um ein Bild aus einem Text-Prompt zu erzeugen, führen Diffusionsmodelle typischerweise die folgenden Schritte aus:
1. **Textkodierung**: Der Text-Prompt wird mithilfe eines Text-Encoders (z. B. eines Transformer-basierten Modells) in eine latente Repräsentation kodiert. Diese Repräsentation erfasst die semantische Bedeutung des Textes.
2. **Rausch-Sampling**: Ein zufälliger Rauschvektor wird aus einer Gaußverteilung gesampelt.
3. **Diffusionsschritte**: Das Modell wendet eine Reihe von Diffusionsschritten an und transformiert den Rauschvektor schrittweise in ein Bild, das dem Text-Prompt entspricht. Jeder Schritt umfasst die Anwendung erlernter Transformationen, um das Bild zu entrauschen.

## References

- [1] [PyTorch - Tutorial zu neuronalen Netzen](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Denoising Diffusion Probabilistic Models](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
