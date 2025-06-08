# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning

Deep Learning ist ein Teilbereich des maschinellen Lernens, der neuronale Netzwerke mit mehreren Schichten (tiefe neuronale Netzwerke) verwendet, um komplexe Muster in Daten zu modellieren. Es hat bemerkenswerte Erfolge in verschiedenen Bereichen erzielt, einschließlich Computer Vision, Verarbeitung natürlicher Sprache und Spracherkennung.

### Neural Networks

Neuronale Netzwerke sind die Bausteine des Deep Learning. Sie bestehen aus miteinander verbundenen Knoten (Neuronen), die in Schichten organisiert sind. Jedes Neuron erhält Eingaben, wendet eine gewichtete Summe an und gibt das Ergebnis durch eine Aktivierungsfunktion weiter, um eine Ausgabe zu erzeugen. Die Schichten können wie folgt kategorisiert werden:
- **Input Layer**: Die erste Schicht, die die Eingabedaten erhält.
- **Hidden Layers**: Zwischenebenen, die Transformationen auf die Eingabedaten durchführen. Die Anzahl der versteckten Schichten und Neuronen in jeder Schicht kann variieren, was zu unterschiedlichen Architekturen führt.
- **Output Layer**: Die letzte Schicht, die die Ausgabe des Netzwerks erzeugt, wie z.B. Klassenwahrscheinlichkeiten in Klassifizierungsaufgaben.

### Activation Functions

Wenn eine Schicht von Neuronen Eingabedaten verarbeitet, wendet jedes Neuron ein Gewicht und einen Bias auf die Eingabe an (`z = w * x + b`), wobei `w` das Gewicht, `x` die Eingabe und `b` der Bias ist. Die Ausgabe des Neurons wird dann durch eine **Aktivierungsfunktion geleitet, um Nichtlinearität** in das Modell einzuführen. Diese Aktivierungsfunktion zeigt im Wesentlichen an, ob das nächste Neuron "aktiviert werden sollte und wie stark". Dies ermöglicht es dem Netzwerk, komplexe Muster und Beziehungen in den Daten zu lernen, wodurch es in der Lage ist, jede kontinuierliche Funktion zu approximieren.

Daher führen Aktivierungsfunktionen Nichtlinearität in das neuronale Netzwerk ein, was es ihm ermöglicht, komplexe Beziehungen in den Daten zu lernen. Zu den gängigen Aktivierungsfunktionen gehören:
- **Sigmoid**: Ordnet Eingabewerte einem Bereich zwischen 0 und 1 zu, oft verwendet in der binären Klassifikation.
- **ReLU (Rectified Linear Unit)**: Gibt die Eingabe direkt aus, wenn sie positiv ist; andernfalls gibt sie null aus. Sie wird aufgrund ihrer Einfachheit und Effektivität beim Training tiefer Netzwerke häufig verwendet.
- **Tanh**: Ordnet Eingabewerte einem Bereich zwischen -1 und 1 zu, oft verwendet in versteckten Schichten.
- **Softmax**: Wandelt rohe Werte in Wahrscheinlichkeiten um, oft verwendet in der Ausgabeschicht für die Mehrklassenklassifikation.

### Backpropagation

Backpropagation ist der Algorithmus, der verwendet wird, um neuronale Netzwerke zu trainieren, indem die Gewichte der Verbindungen zwischen Neuronen angepasst werden. Er funktioniert, indem er den Gradienten der Verlustfunktion in Bezug auf jedes Gewicht berechnet und die Gewichte in die entgegengesetzte Richtung des Gradienten aktualisiert, um den Verlust zu minimieren. Die Schritte, die an der Backpropagation beteiligt sind, sind:

1. **Forward Pass**: Berechne die Ausgabe des Netzwerks, indem du die Eingabe durch die Schichten leitest und Aktivierungsfunktionen anwendest.
2. **Loss Calculation**: Berechne den Verlust (Fehler) zwischen der vorhergesagten Ausgabe und dem tatsächlichen Ziel unter Verwendung einer Verlustfunktion (z.B. mittlerer quadratischer Fehler für Regression, Kreuzentropie für Klassifikation).
3. **Backward Pass**: Berechne die Gradienten des Verlusts in Bezug auf jedes Gewicht unter Verwendung der Kettenregel der Analysis.
4. **Weight Update**: Aktualisiere die Gewichte mit einem Optimierungsalgorithmus (z.B. stochastischer Gradientenabstieg, Adam), um den Verlust zu minimieren.

## Convolutional Neural Networks (CNNs)

Convolutional Neural Networks (CNNs) sind eine spezialisierte Art von neuronalen Netzwerken, die für die Verarbeitung von gitterartigen Daten, wie z.B. Bildern, entwickelt wurden. Sie sind besonders effektiv bei Aufgaben der Computer Vision aufgrund ihrer Fähigkeit, räumliche Hierarchien von Merkmalen automatisch zu lernen.

Die Hauptkomponenten von CNNs umfassen:
- **Convolutional Layers**: Wenden Faltungsoperationen auf die Eingabedaten unter Verwendung lernbarer Filter (Kerne) an, um lokale Merkmale zu extrahieren. Jeder Filter gleitet über die Eingabe und berechnet ein Skalarprodukt, wodurch eine Merkmalskarte entsteht.
- **Pooling Layers**: Reduzieren die räumlichen Dimensionen der Merkmalskarten, während wichtige Merkmale beibehalten werden. Zu den gängigen Pooling-Operationen gehören Max-Pooling und Average-Pooling.
- **Fully Connected Layers**: Verbinden jedes Neuron in einer Schicht mit jedem Neuron in der nächsten Schicht, ähnlich wie traditionelle neuronale Netzwerke. Diese Schichten werden typischerweise am Ende des Netzwerks für Klassifikationsaufgaben verwendet.

Innerhalb eines CNN **`Convolutional Layers`** können wir auch zwischen unterscheiden:
- **Initial Convolutional Layer**: Die erste Faltungsschicht, die die Rohdaten (z.B. ein Bild) verarbeitet und nützlich ist, um grundlegende Merkmale wie Kanten und Texturen zu identifizieren.
- **Intermediate Convolutional Layers**: Nachfolgende Faltungsschichten, die auf den von der ersten Schicht gelernten Merkmalen aufbauen und es dem Netzwerk ermöglichen, komplexere Muster und Darstellungen zu lernen.
- **Final Convolutional Layer**: Die letzten Faltungsschichten vor den vollständig verbundenen Schichten, die hochgradige Merkmale erfassen und die Daten für die Klassifikation vorbereiten.

> [!TIP]
> CNNs sind besonders effektiv für Aufgaben der Bildklassifikation, Objekterkennung und Bildsegmentierung, da sie in der Lage sind, räumliche Hierarchien von Merkmalen in gitterartigen Daten zu lernen und die Anzahl der Parameter durch Gewichtsteilung zu reduzieren.
> Darüber hinaus funktionieren sie besser mit Daten, die das Prinzip der Merkmalslokalität unterstützen, bei dem benachbarte Daten (Pixel) wahrscheinlicher miteinander verwandt sind als entfernte Pixel, was bei anderen Datentypen wie Text möglicherweise nicht der Fall ist.
> Darüber hinaus beachten Sie, dass CNNs in der Lage sind, selbst komplexe Merkmale zu identifizieren, jedoch keinen räumlichen Kontext anwenden können, was bedeutet, dass dasselbe Merkmal, das in verschiedenen Teilen des Bildes gefunden wird, dasselbe sein wird.

### Example defining a CNN

*Hier finden Sie eine Beschreibung, wie man ein Convolutional Neural Network (CNN) in PyTorch definiert, das mit einem Batch von RGB-Bildern als Datensatz der Größe 48x48 beginnt und Faltungsschichten und Max-Pooling verwendet, um Merkmale zu extrahieren, gefolgt von vollständig verbundenen Schichten für die Klassifikation.*

So können Sie 1 Faltungsschicht in PyTorch definieren: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Anzahl der Eingabekanäle. Im Fall von RGB-Bildern sind dies 3 (einer für jeden Farbkanal). Wenn Sie mit Graustufenbildern arbeiten, wäre dies 1.

- `out_channels`: Anzahl der Ausgabekanäle (Filter), die die Faltungsschicht lernen wird. Dies ist ein Hyperparameter, den Sie basierend auf Ihrer Modellarchitektur anpassen können.

- `kernel_size`: Größe des Faltungfilters. Eine gängige Wahl ist 3x3, was bedeutet, dass der Filter einen Bereich von 3x3 im Eingabebild abdeckt. Dies ist wie ein 3×3×3 Farbstempel, der verwendet wird, um die out_channels aus den in_channels zu generieren:
1. Platzieren Sie diesen 3×3×3 Stempel in der oberen linken Ecke des Bildwürfels.
2. Multiplizieren Sie jedes Gewicht mit dem Pixel darunter, addieren Sie sie alle, addieren Sie den Bias → Sie erhalten eine Zahl.
3. Schreiben Sie diese Zahl in eine leere Karte an der Position (0, 0).
4. Gleiten Sie den Stempel um ein Pixel nach rechts (Stride = 1) und wiederholen Sie den Vorgang, bis Sie ein ganzes 48×48 Raster gefüllt haben.

- `padding`: Anzahl der Pixel, die auf jede Seite der Eingabe hinzugefügt werden. Padding hilft, die räumlichen Dimensionen der Eingabe zu erhalten, was mehr Kontrolle über die Ausgabedimension ermöglicht. Zum Beispiel wird bei einem 3x3-Kernel und einer 48x48-Pixel-Eingabe mit einem Padding von 1 die Ausgabedimension gleich bleiben (48x48) nach der Faltungsoperation. Dies liegt daran, dass das Padding einen Rand von 1 Pixel um das Eingabebild hinzufügt, sodass der Kernel über die Ränder gleiten kann, ohne die räumlichen Dimensionen zu reduzieren.

Dann beträgt die Anzahl der trainierbaren Parameter in dieser Schicht:
- (3x3x3 (Kernelgröße) + 1 (Bias)) x 32 (out_channels) = 896 trainierbare Parameter.

Beachten Sie, dass ein Bias (+1) pro verwendetem Kernel hinzugefügt wird, da die Funktion jeder Faltungsschicht darin besteht, eine lineare Transformation der Eingabe zu lernen, die durch die Gleichung dargestellt wird:
```plaintext
Y = f(W * X + b)
```
wo `W` die Gewichtsmatrix (die gelernten Filter, 3x3x3 = 27 Parameter) ist, `b` der Bias-Vektor, der für jeden Ausgabekanal +1 beträgt.

Beachten Sie, dass die Ausgabe von `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` ein Tensor der Form `(batch_size, 32, 48, 48)` sein wird, da 32 die neue Anzahl der generierten Kanäle mit einer Größe von 48x48 Pixeln ist.

Dann könnten wir diese Convolutional-Schicht mit einer anderen Convolutional-Schicht verbinden, wie: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Was hinzufügen wird: (32x3x3 (Kernelgröße) + 1 (Bias)) x 64 (Ausgabekanäle) = 18.496 trainierbare Parameter und eine Ausgabe der Form `(batch_size, 64, 48, 48)`.

Wie Sie sehen können, **wächst die Anzahl der Parameter schnell mit jeder zusätzlichen Convolutional-Schicht**, insbesondere wenn die Anzahl der Ausgabekanäle zunimmt.

Eine Möglichkeit, die Menge der verwendeten Daten zu steuern, besteht darin, **Max-Pooling** nach jeder Convolutional-Schicht zu verwenden. Max-Pooling reduziert die räumlichen Dimensionen der Merkmalskarten, was hilft, die Anzahl der Parameter und die rechnerische Komplexität zu reduzieren, während wichtige Merkmale erhalten bleiben.

Es kann erklärt werden als: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Dies zeigt im Wesentlichen an, dass ein Gitter von 2x2 Pixeln verwendet wird und der maximale Wert aus jedem Gitter entnommen wird, um die Größe der Merkmalskarte um die Hälfte zu reduzieren. Darüber hinaus bedeutet `stride=2`, dass die Pooling-Operation 2 Pixel auf einmal bewegt, in diesem Fall, um eine Überlappung zwischen den Pooling-Bereichen zu verhindern.

Mit dieser Pooling-Schicht wäre die Ausgabedimension nach der ersten Convolutional-Schicht `(batch_size, 64, 24, 24)`, nachdem `self.pool1` auf die Ausgabe von `self.conv2` angewendet wurde, wodurch die Größe auf ein Viertel der vorherigen Schicht reduziert wird.

> [!TIP]
> Es ist wichtig, nach den Convolutional-Schichten zu poolen, um die räumlichen Dimensionen der Merkmalskarten zu reduzieren, was hilft, die Anzahl der Parameter und die rechnerische Komplexität zu steuern, während die anfänglichen Parameter wichtige Merkmale lernen.
> Sie können die Faltungen vor einer Pooling-Schicht als eine Möglichkeit sehen, Merkmale aus den Eingabedaten (wie Linien, Kanten) zu extrahieren. Diese Informationen werden weiterhin in der gepoolten Ausgabe vorhanden sein, aber die nächste Convolutional-Schicht wird die ursprünglichen Eingabedaten nicht sehen können, nur die gepoolte Ausgabe, die eine reduzierte Version der vorherigen Schicht mit diesen Informationen ist.
> In der üblichen Reihenfolge: `Conv → ReLU → Pool` konkurriert jedes 2×2-Pooling-Fenster jetzt mit Merkmalsaktivierungen (“Kante vorhanden / nicht”), nicht mit rohen Pixelintensitäten. Die stärkste Aktivierung zu behalten, bewahrt wirklich die auffälligsten Beweise.

Nachdem wir dann so viele Convolutional- und Pooling-Schichten hinzugefügt haben, wie benötigt werden, können wir die Ausgabe abflachen, um sie in vollständig verbundene Schichten einzuspeisen. Dies geschieht, indem der Tensor für jede Probe im Batch in einen 1D-Vektor umgeformt wird:
```python
x = x.view(-1, 64*24*24)
```
Und mit diesem 1D-Vektor, der alle Trainingsparameter enthält, die von den vorherigen konvolutionalen und Pooling-Schichten generiert wurden, können wir eine vollständig verbundene Schicht wie folgt definieren:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Welche die flach ausgegebene Ausgabe der vorherigen Schicht nimmt und sie auf 512 versteckte Einheiten abbildet.

Beachten Sie, wie diese Schicht `(64 * 24 * 24 + 1 (Bias)) * 512 = 3.221.504` trainierbare Parameter hinzugefügt hat, was im Vergleich zu den konvolutionalen Schichten einen signifikanten Anstieg darstellt. Dies liegt daran, dass vollständig verbundene Schichten jedes Neuron in einer Schicht mit jedem Neuron in der nächsten Schicht verbinden, was zu einer großen Anzahl von Parametern führt.

Schließlich können wir eine Ausgabeschicht hinzufügen, um die endgültigen Klassenlogits zu erzeugen:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Dies wird `(512 + 1 (Bias)) * num_classes` trainierbare Parameter hinzufügen, wobei `num_classes` die Anzahl der Klassen in der Klassifizierungsaufgabe ist (z. B. 43 für den GTSRB-Datensatz).

Eine weitere gängige Praxis ist es, eine Dropout-Schicht vor den vollständig verbundenen Schichten hinzuzufügen, um Überanpassung zu verhindern. Dies kann mit:
```python
self.dropout = nn.Dropout(0.5)
```
Diese Schicht setzt während des Trainings zufällig einen Bruchteil der Eingabeeinheiten auf null, was hilft, Überanpassung zu verhindern, indem die Abhängigkeit von bestimmten Neuronen verringert wird.

### CNN Codebeispiel
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
### CNN Code-Trainingsbeispiel

Der folgende Code erstellt einige Trainingsdaten und trainiert das oben definierte `MY_NET`-Modell. Einige interessante Werte, die zu beachten sind:

- `EPOCHS` ist die Anzahl der Male, die das Modell während des Trainings den gesamten Datensatz sieht. Wenn EPOCH zu klein ist, lernt das Modell möglicherweise nicht genug; wenn es zu groß ist, kann es überanpassen.
- `LEARNING_RATE` ist die Schrittgröße für den Optimierer. Eine kleine Lernrate kann zu langsamer Konvergenz führen, während eine große die optimale Lösung überschießen und die Konvergenz verhindern kann.
- `WEIGHT_DECAY` ist ein Regularisierungsterm, der hilft, Überanpassung zu verhindern, indem große Gewichte bestraft werden.

Bezüglich der Trainingsschleife gibt es einige interessante Informationen zu wissen:
- Die `criterion = nn.CrossEntropyLoss()` ist die Verlustfunktion, die für Mehrklassenklassifikationsaufgaben verwendet wird. Sie kombiniert die Softmax-Aktivierung und den Kreuzentropie-Verlust in einer einzigen Funktion, was sie für das Training von Modellen, die Klassenlogits ausgeben, geeignet macht.
- Wenn das Modell erwartet wurde, andere Arten von Ausgaben zu erzeugen, wie binäre Klassifikation oder Regression, würden wir andere Verlustfunktionen wie `nn.BCEWithLogitsLoss()` für die binäre Klassifikation oder `nn.MSELoss()` für die Regression verwenden.
- Der `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` initialisiert den Adam-Optimierer, der eine beliebte Wahl für das Training von Deep-Learning-Modellen ist. Er passt die Lernrate für jeden Parameter basierend auf den ersten und zweiten Momenten der Gradienten an.
- Andere Optimierer wie `optim.SGD` (Stochastic Gradient Descent) oder `optim.RMSprop` könnten ebenfalls verwendet werden, abhängig von den spezifischen Anforderungen der Trainingsaufgabe.
- Die `model.train()`-Methode setzt das Modell in den Trainingsmodus, wodurch Schichten wie Dropout und Batch-Normalisierung sich während des Trainings anders verhalten als bei der Auswertung.
- `optimizer.zero_grad()` löscht die Gradienten aller optimierten Tensoren vor dem Rückwärtsdurchlauf, was notwendig ist, da Gradienten standardmäßig in PyTorch akkumuliert werden. Wenn sie nicht gelöscht werden, würden die Gradienten aus vorherigen Iterationen zu den aktuellen Gradienten addiert, was zu falschen Aktualisierungen führen würde.
- `loss.backward()` berechnet die Gradienten des Verlusts in Bezug auf die Modellparameter, die dann vom Optimierer verwendet werden, um die Gewichte zu aktualisieren.
- `optimizer.step()` aktualisiert die Modellparameter basierend auf den berechneten Gradienten und der Lernrate.
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
## Rekurrente Neuronale Netze (RNNs)

Rekurrente Neuronale Netze (RNNs) sind eine Klasse von neuronalen Netzen, die für die Verarbeitung sequentieller Daten, wie Zeitreihen oder natürliche Sprache, entwickelt wurden. Im Gegensatz zu traditionellen Feedforward-Neuronalen Netzen haben RNNs Verbindungen, die auf sich selbst zurückführen, was es ihnen ermöglicht, einen verborgenen Zustand aufrechtzuerhalten, der Informationen über vorherige Eingaben in der Sequenz erfasst.

Die Hauptkomponenten von RNNs umfassen:
- **Rekurrente Schichten**: Diese Schichten verarbeiten Eingabesequenzen Schritt für Schritt und aktualisieren ihren verborgenen Zustand basierend auf der aktuellen Eingabe und dem vorherigen verborgenen Zustand. Dies ermöglicht es RNNs, zeitliche Abhängigkeiten in den Daten zu lernen.
- **Verborgenes Zustand**: Der verborgene Zustand ist ein Vektor, der die Informationen aus vorherigen Zeitpunkten zusammenfasst. Er wird in jedem Zeitintervall aktualisiert und wird verwendet, um Vorhersagen für die aktuelle Eingabe zu treffen.
- **Ausgabeschicht**: Die Ausgabeschicht erzeugt die endgültigen Vorhersagen basierend auf dem verborgenen Zustand. In vielen Fällen werden RNNs für Aufgaben wie Sprachmodellierung verwendet, bei denen die Ausgabe eine Wahrscheinlichkeitsverteilung über das nächste Wort in einer Sequenz ist.

Zum Beispiel verarbeitet das RNN in einem Sprachmodell eine Sequenz von Wörtern, zum Beispiel "Die Katze saß auf dem" und sagt das nächste Wort basierend auf dem Kontext, der durch die vorherigen Wörter bereitgestellt wird, in diesem Fall "Teppich".

### Langzeit-Kurzzeit-Gedächtnis (LSTM) und Gated Recurrent Unit (GRU)

RNNs sind besonders effektiv für Aufgaben, die sequentielle Daten betreffen, wie Sprachmodellierung, maschinelle Übersetzung und Spracherkennung. Sie können jedoch mit **langfristigen Abhängigkeiten aufgrund von Problemen wie verschwindenden Gradienten** kämpfen.

Um dies zu beheben, wurden spezialisierte Architekturen wie Langzeit-Kurzzeit-Gedächtnis (LSTM) und Gated Recurrent Unit (GRU) entwickelt. Diese Architekturen führen Steuermechanismen ein, die den Fluss von Informationen kontrollieren und es ihnen ermöglichen, langfristige Abhängigkeiten effektiver zu erfassen.

- **LSTM**: LSTM-Netzwerke verwenden drei Tore (Eingangstor, Vergessenstor und Ausgangstor), um den Fluss von Informationen in und aus dem Zellzustand zu regulieren, wodurch sie Informationen über lange Sequenzen hinweg behalten oder vergessen können. Das Eingangstor steuert, wie viel neue Informationen basierend auf der Eingabe und dem vorherigen verborgenen Zustand hinzugefügt werden, das Vergessenstor steuert, wie viel Informationen verworfen werden. Durch die Kombination des Eingangstors und des Vergessenstors erhalten wir den neuen Zustand. Schließlich erhalten wir durch die Kombination des neuen Zellzustands mit der Eingabe und dem vorherigen verborgenen Zustand auch den neuen verborgenen Zustand.
- **GRU**: GRU-Netzwerke vereinfachen die LSTM-Architektur, indem sie das Eingangs- und Vergessenstor in ein einzelnes Aktualisierungstor kombinieren, was sie rechnerisch effizienter macht und dennoch langfristige Abhängigkeiten erfasst.

## LLMs (Große Sprachmodelle)

Große Sprachmodelle (LLMs) sind eine Art von Deep-Learning-Modell, das speziell für Aufgaben der natürlichen Sprachverarbeitung entwickelt wurde. Sie werden mit riesigen Mengen an Textdaten trainiert und können menschenähnlichen Text generieren, Fragen beantworten, Sprachen übersetzen und verschiedene andere sprachbezogene Aufgaben ausführen. LLMs basieren typischerweise auf Transformer-Architekturen, die Selbstaufmerksamkeitsmechanismen verwenden, um Beziehungen zwischen Wörtern in einer Sequenz zu erfassen, was es ihnen ermöglicht, den Kontext zu verstehen und kohärenten Text zu generieren.

### Transformer-Architektur
Die Transformer-Architektur ist die Grundlage vieler LLMs. Sie besteht aus einer Encoder-Decoder-Struktur, wobei der Encoder die Eingabesequenz verarbeitet und der Decoder die Ausgabesequenz generiert. Die Schlüsselkomponenten der Transformer-Architektur umfassen:
- **Selbstaufmerksamkeitsmechanismus**: Dieser Mechanismus ermöglicht es dem Modell, die Bedeutung verschiedener Wörter in einer Sequenz beim Generieren von Repräsentationen zu gewichten. Er berechnet Aufmerksamkeitswerte basierend auf den Beziehungen zwischen Wörtern, sodass das Modell sich auf relevanten Kontext konzentrieren kann.
- **Multi-Head Attention**: Diese Komponente ermöglicht es dem Modell, mehrere Beziehungen zwischen Wörtern zu erfassen, indem mehrere Aufmerksamkeitsköpfe verwendet werden, die jeweils auf verschiedene Aspekte der Eingabe fokussieren.
- **Positionskodierung**: Da Transformer kein eingebautes Konzept der Wortreihenfolge haben, wird der Eingaberepräsentation Positionskodierung hinzugefügt, um Informationen über die Position der Wörter in der Sequenz bereitzustellen.

## Diffusionsmodelle
Diffusionsmodelle sind eine Klasse von generativen Modellen, die lernen, Daten zu generieren, indem sie einen Diffusionsprozess simulieren. Sie sind besonders effektiv für Aufgaben wie die Bildgenerierung und haben in den letzten Jahren an Popularität gewonnen. Diffusionsmodelle funktionieren, indem sie schrittweise eine einfache Rauschverteilung in eine komplexe Datenverteilung durch eine Reihe von Diffusionsschritten umwandeln. Die Schlüsselkomponenten von Diffusionsmodellen umfassen:
- **Vorwärtsdiffusionsprozess**: Dieser Prozess fügt schrittweise Rauschen zu den Daten hinzu und verwandelt sie in eine einfache Rauschverteilung. Der Vorwärtsdiffusionsprozess wird typischerweise durch eine Reihe von Rauschpegeln definiert, wobei jeder Pegel einer bestimmten Menge von Rauschen entspricht, die den Daten hinzugefügt wird.
- **Rückwärtsdiffusionsprozess**: Dieser Prozess lernt, den Vorwärtsdiffusionsprozess umzukehren, indem er die Daten schrittweise entrauscht, um Proben aus der Zielverteilung zu generieren. Der Rückwärtsdiffusionsprozess wird mit einer Verlustfunktion trainiert, die das Modell dazu anregt, die ursprünglichen Daten aus verrauschten Proben zu rekonstruieren.

Darüber hinaus folgen Diffusionsmodelle typischerweise diesen Schritten, um ein Bild aus einem Textprompt zu generieren:
1. **Textkodierung**: Der Textprompt wird mit einem Textencoder (z. B. einem transformerbasierten Modell) in eine latente Repräsentation kodiert. Diese Repräsentation erfasst die semantische Bedeutung des Textes.
2. **Rauschsampling**: Ein zufälliger Rauschvektor wird aus einer Gaußschen Verteilung entnommen.
3. **Diffusionsschritte**: Das Modell wendet eine Reihe von Diffusionsschritten an, um den Rauschvektor schrittweise in ein Bild zu verwandeln, das dem Textprompt entspricht. Jeder Schritt beinhaltet das Anwenden von gelernten Transformationen, um das Bild zu entrauschen.

{{#include ../banners/hacktricks-training.md}}
