# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning <sup>[[1]](#references)</sup>

Il deep learning è un sottoinsieme del machine learning che utilizza reti neurali con più livelli (reti neurali profonde) per modellare pattern complessi nei dati. Ha ottenuto risultati notevoli in vari ambiti, tra cui computer vision, natural language processing e riconoscimento vocale.

### Neural Networks

Le reti neurali sono i componenti fondamentali del deep learning. Sono costituite da nodi interconnessi (neuroni) organizzati in livelli. Ogni neurone riceve degli input, applica una somma pesata e passa il risultato attraverso una funzione di attivazione per produrre un output. I livelli possono essere classificati come segue:
- **Input Layer**: il primo livello che riceve i dati di input.
- **Hidden Layers**: livelli intermedi che eseguono trasformazioni sui dati di input. Il numero di livelli nascosti e di neuroni in ciascun livello può variare, portando ad architetture diverse.
- **Output Layer**: il livello finale che produce l'output della rete, come le probabilità delle classi nei task di classificazione.


### Activation Functions

Quando un livello di neuroni elabora i dati di input, ogni neurone applica un peso e un bias all'input (`z = w * x + b`), dove `w` è il peso, `x` è l'input e `b` è il bias. L'output del neurone viene quindi passato attraverso una **funzione di attivazione per introdurre non linearità** nel modello. Questa funzione di attivazione indica sostanzialmente se il neurone successivo "dovrebbe essere attivato e in quale misura". Ciò consente alla rete di apprendere pattern e relazioni complessi nei dati, permettendole di approssimare qualsiasi funzione continua.

Pertanto, le funzioni di attivazione introducono non linearità nella rete neurale, consentendole di apprendere relazioni complesse nei dati. Le funzioni di attivazione comuni includono:
- **Sigmoid**: mappa i valori di input in un intervallo compreso tra 0 e 1, spesso utilizzata nella classificazione binaria.
- **ReLU (Rectified Linear Unit)**: restituisce direttamente l'input se è positivo; altrimenti restituisce zero. È ampiamente utilizzata grazie alla sua semplicità ed efficacia nell'addestramento di reti profonde.
- **Tanh**: mappa i valori di input in un intervallo compreso tra -1 e 1, spesso utilizzata nei livelli nascosti.
- **Softmax**: converte i punteggi grezzi in probabilità, spesso utilizzata nel livello di output per la classificazione multi-classe.

### Backpropagation

La backpropagation è l'algoritmo utilizzato per addestrare le reti neurali regolando i pesi delle connessioni tra i neuroni. Funziona calcolando il gradiente della funzione di loss rispetto a ciascun peso e aggiornando i pesi nella direzione opposta a quella del gradiente, per minimizzare la loss. I passaggi coinvolti nella backpropagation sono:

1. **Forward Pass**: calcolare l'output della rete passando l'input attraverso i livelli e applicando le funzioni di attivazione.
2. **Loss Calculation**: calcolare la loss (errore) tra l'output previsto e il target reale utilizzando una funzione di loss (ad esempio, l'errore quadratico medio per la regressione e la cross-entropy per la classificazione).
3. **Backward Pass**: calcolare i gradienti della loss rispetto a ciascun peso utilizzando la chain rule del calcolo differenziale.
4. **Weight Update**: aggiornare i pesi utilizzando un algoritmo di ottimizzazione (ad esempio, stochastic gradient descent o Adam) per minimizzare la loss.

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Le Convolutional Neural Networks (CNNs) sono un tipo specializzato di rete neurale progettato per elaborare dati organizzati su una griglia, come le immagini. Sono particolarmente efficaci nei task di computer vision grazie alla loro capacità di apprendere automaticamente gerarchie spaziali di feature.

I componenti principali delle CNN includono:
- **Convolutional Layers**: applicano operazioni di convoluzione ai dati di input utilizzando filtri apprendibili (kernel) per estrarre feature locali. Ogni filtro scorre sull'input e calcola un prodotto scalare, producendo una feature map.
- **Pooling Layers**: eseguono il downsampling delle feature map per ridurne le dimensioni spaziali, conservando al contempo le feature importanti. Le operazioni di pooling comuni includono il max pooling e l'average pooling.
- **Fully Connected Layers**: connettono ogni neurone di un livello a ogni neurone del livello successivo, in modo simile alle reti neurali tradizionali. Questi livelli vengono generalmente utilizzati alla fine della rete per i task di classificazione.

All'interno dei **`Convolutional Layers`** di una CNN, possiamo inoltre distinguere tra:
- **Initial Convolutional Layer**: il primo livello convoluzionale che elabora i dati di input grezzi (ad esempio, un'immagine) ed è utile per identificare feature di base come bordi e texture.
- **Intermediate Convolutional Layers**: i successivi livelli convoluzionali che si basano sulle feature apprese dal livello iniziale, consentendo alla rete di apprendere pattern e rappresentazioni più complessi.
- **Final Convolutional Layer**: gli ultimi livelli convoluzionali prima dei livelli fully connected, che catturano feature di alto livello e preparano i dati per la classificazione.

> [!TIP]
> Le CNN sono particolarmente efficaci per i task di classificazione delle immagini, object detection e image segmentation grazie alla loro capacità di apprendere gerarchie spaziali di feature nei dati organizzati su una griglia e di ridurre il numero di parametri tramite la condivisione dei pesi.
> Inoltre, funzionano meglio con dati che supportano il principio di località delle feature, secondo cui i dati vicini (pixel) hanno maggiori probabilità di essere correlati rispetto ai pixel distanti, cosa che potrebbe non valere per altri tipi di dati, come il testo.
> Inoltre, è importante notare che le CNN sono in grado di identificare anche feature complesse, ma non possono applicare alcun contesto spaziale; ciò significa che la stessa feature trovata in parti diverse dell'immagine sarà considerata la stessa.

### Example defining a CNN

*Qui troverai una descrizione di come definire una Convolutional Neural Network (CNN) in PyTorch, che inizia con un batch di immagini RGB come dataset di dimensioni 48x48 e utilizza livelli convoluzionali e maxpool per estrarre le feature, seguiti da livelli fully connected per la classificazione.*

Ecco come puoi definire 1 livello convoluzionale in PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: numero di canali di input. Nel caso di immagini RGB, è 3 (uno per ciascun canale di colore). Se lavori con immagini in scala di grigi, sarebbe 1.

- `out_channels`: numero di canali di output (filtri) che il livello convoluzionale apprenderà. Questo è un iperparametro che puoi modificare in base all'architettura del modello.

- `kernel_size`: dimensione del filtro convoluzionale. Una scelta comune è 3x3, il che significa che il filtro coprirà un'area 3x3 dell'immagine di input. È come un timbro di colore 3×3×3 utilizzato per generare gli out_channels dagli in_channels:
1. Posiziona il timbro 3×3×3 nell'angolo superiore sinistro del cubo dell'immagine.
2. Moltiplica ogni peso per il pixel sottostante, somma tutti i valori e aggiungi il bias → ottieni un numero.
3. Scrivi quel numero in una mappa vuota nella posizione (0, 0).
4. Fai scorrere il timbro di un pixel verso destra (stride = 1) e ripeti fino a riempire un'intera griglia 48×48.

- `padding`: numero di pixel aggiunti a ciascun lato dell'input. Il padding aiuta a preservare le dimensioni spaziali dell'input, consentendo un maggiore controllo sulla dimensione dell'output. Ad esempio, con un kernel 3x3 e un input di 48x48 pixel, un padding pari a 1 manterrà invariata la dimensione dell'output (48x48) dopo l'operazione di convoluzione. Questo avviene perché il padding aggiunge un bordo di 1 pixel intorno all'immagine di input, consentendo al kernel di scorrere sui bordi senza ridurre le dimensioni spaziali.

Quindi, il numero di parametri addestrabili in questo livello è:
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 parametri addestrabili.

Tieni presente che viene aggiunto un Bias (+1) per ogni kernel utilizzato, perché la funzione di ogni livello convoluzionale è apprendere una trasformazione lineare dell'input, rappresentata dall'equazione:
```plaintext
Y = f(W * X + b)
```
dove `W` è la matrice dei pesi (i filtri appresi, 3x3x3 = 27 parametri), `b` è il vettore dei bias, che vale +1 per ogni canale di output.

Si noti che l'output di `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` sarà un tensore di forma `(batch_size, 32, 48, 48)`, perché 32 è il nuovo numero di canali generati di dimensione 48x48 pixel.

Quindi, potremmo collegare questo convolutional layer a un altro convolutional layer, ad esempio: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Questo aggiungerà: (32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 parametri addestrabili e un output di forma `(batch_size, 64, 48, 48)`.

Come si può vedere, il **numero di parametri cresce rapidamente con ogni convolutional layer aggiuntivo**, soprattutto all'aumentare del numero di canali di output.

Un'opzione per controllare la quantità di dati utilizzati consiste nell'usare il **max pooling** dopo ogni convolutional layer. Il max pooling riduce le dimensioni spaziali delle feature map, contribuendo a ridurre il numero di parametri e la complessità computazionale, mantenendo al contempo le feature importanti.

Può essere dichiarato come: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Questo indica fondamentalmente di utilizzare una griglia di 2x2 pixel e prendere il valore massimo da ogni griglia per ridurre della metà la dimensione della feature map. Inoltre, `stride=2` significa che l'operazione di pooling si sposterà di 2 pixel alla volta, impedendo in questo caso qualsiasi sovrapposizione tra le regioni di pooling.

Con questo pooling layer, la forma dell'output dopo il primo convolutional layer sarebbe `(batch_size, 64, 24, 24)` dopo aver applicato `self.pool1` all'output di `self.conv2`, riducendo la dimensione a 1/4 rispetto al layer precedente.

> [!TIP]
> È importante applicare il pooling dopo i convolutional layer per ridurre le dimensioni spaziali delle feature map, contribuendo a controllare il numero di parametri e la complessità computazionale e consentendo al contempo al parametro iniziale di apprendere feature importanti.
>Si possono vedere le convoluzioni prima di un pooling layer come un modo per estrarre feature dai dati di input (come linee e bordi); queste informazioni saranno ancora presenti nell'output sottoposto a pooling, ma il convolutional layer successivo non sarà in grado di vedere i dati di input originali, bensì solo l'output sottoposto a pooling, che è una versione ridotta del layer precedente contenente tali informazioni.
>Nell'ordine abituale: `Conv → ReLU → Pool`, ogni finestra di pooling 2×2 si confronta ora con le attivazioni delle feature ("bordo presente / assente"), non con le intensità dei pixel grezzi. Mantenere l'attivazione più forte significa davvero conservare l'evidenza più rilevante.

Dopo aver aggiunto tutti i convolutional layer e pooling layer necessari, possiamo appiattire l'output per passarlo ai fully connected layer. Questo viene fatto ridimensionando il tensore in un vettore 1D per ogni campione del batch:
```python
x = x.view(-1, 64*24*24)
```
E con questo vettore 1D contenente tutti i parametri di training generati dai precedenti layer convoluzionali e di pooling, possiamo definire un layer fully connected come:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Che prenderà l'output appiattito del layer precedente e lo mapperà a 512 unità nascoste.

Nota come questo layer abbia aggiunto `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` parametri addestrabili, un aumento significativo rispetto ai layer convoluzionali. Questo perché i layer fully connected collegano ogni neurone di un layer a ogni neurone del layer successivo, producendo un numero elevato di parametri.

Infine, possiamo aggiungere un layer di output per produrre i logits finali delle classi:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Questo aggiungerà `(512 + 1 (bias)) * num_classes` parametri addestrabili, dove `num_classes` è il numero di classi nell'attività di classificazione (ad esempio, 43 per il dataset GTSRB).

Un'altra pratica comune è aggiungere un layer di dropout prima dei layer completamente connessi per prevenire l'overfitting. Questo può essere fatto con:
```python
self.dropout = nn.Dropout(0.5)
```
Questo livello imposta casualmente a zero una frazione delle unità di input durante l'addestramento, contribuendo a prevenire l'overfitting riducendo la dipendenza da neuroni specifici.

### Esempio di codice CNN
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
### Esempio di training del codice CNN

Il codice seguente genererà alcuni training data ed eseguirà il training del modello `MY_NET` definito sopra. Alcuni valori interessanti da notare:

- `EPOCHS` indica il numero di volte in cui il modello vedrà l'intero dataset durante il training. Se EPOCH è troppo piccolo, il modello potrebbe non imparare abbastanza; se è troppo grande, potrebbe andare incontro a overfitting.
- `LEARNING_RATE` indica la dimensione del passo per l'optimizer. Un learning rate ridotto può portare a una convergenza lenta, mentre uno elevato potrebbe superare la soluzione ottimale e impedire la convergenza.
- `WEIGHT_DECAY` è un termine di regolarizzazione che aiuta a prevenire l'overfitting penalizzando i pesi elevati.

Per quanto riguarda il training loop, ecco alcune informazioni interessanti da conoscere:
- `criterion = nn.CrossEntropyLoss()` è la loss function utilizzata per i task di classificazione multi-classe. Combina l'attivazione softmax e la cross-entropy loss in un'unica funzione, rendendola adatta al training di modelli che producono class logits.
- Se il modello dovesse produrre altri tipi di output, come classificazione binaria o regressione, useremmo loss function diverse, come `nn.BCEWithLogitsLoss()` per la classificazione binaria o `nn.MSELoss()` per la regressione.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inizializza l'Adam optimizer, una scelta popolare per il training dei modelli di deep learning. Adatta il learning rate per ogni parametro in base al primo e al secondo momento dei gradients.
- Potrebbero essere utilizzati anche altri optimizer, come `optim.SGD` (Stochastic Gradient Descent) o `optim.RMSprop`, in base ai requisiti specifici del training task.
- Il metodo `model.train()` imposta il modello in training mode, consentendo a layer come dropout e batch normalization di comportarsi diversamente durante il training rispetto alla valutazione.
- `optimizer.zero_grad()` cancella i gradients di tutti i tensori sottoposti a ottimizzazione prima del backward pass, operazione necessaria perché in PyTorch i gradients si accumulano per impostazione predefinita. Se non venissero cancellati, i gradients delle iterazioni precedenti verrebbero aggiunti ai gradients correnti, causando aggiornamenti errati.
- `loss.backward()` calcola i gradients della loss rispetto ai parametri del modello, che vengono quindi utilizzati dall'optimizer per aggiornare i pesi.
- `optimizer.step()` aggiorna i parametri del modello in base ai gradients calcolati e al learning rate.
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
## Reti neurali ricorrenti (RNN) <sup>[[3]](#references)</sup>

Le Reti neurali ricorrenti (RNN) sono una classe di reti neurali progettate per elaborare dati sequenziali, come serie temporali o linguaggio naturale. A differenza delle tradizionali reti neurali feedforward, le RNN hanno connessioni che ricostruiscono un ciclo su se stesse, permettendo loro di mantenere uno stato nascosto che acquisisce informazioni sugli input precedenti nella sequenza.

I componenti principali delle RNN includono:
- **Livelli ricorrenti**: questi livelli elaborano le sequenze di input un time step alla volta, aggiornando il proprio stato nascosto in base all'input corrente e allo stato nascosto precedente. Ciò permette alle RNN di apprendere le dipendenze temporali nei dati.
- **Stato nascosto**: lo stato nascosto è un vettore che riassume le informazioni provenienti dai time step precedenti. Viene aggiornato a ogni time step e utilizzato per effettuare previsioni sull'input corrente.
- **Livello di output**: il livello di output produce le previsioni finali in base allo stato nascosto. In molti casi, le RNN vengono utilizzate per attività come il language modeling, in cui l'output è una distribuzione di probabilità sulla parola successiva in una sequenza.

Ad esempio, in un language model, la RNN elabora una sequenza di parole, per esempio, "The cat sat on the" e prevede la parola successiva in base al contesto fornito dalle parole precedenti, in questo caso, "mat".

### Long Short-Term Memory (LSTM) e Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

Le RNN sono particolarmente efficaci per attività che coinvolgono dati sequenziali, come il language modeling, la machine translation e il riconoscimento vocale. Tuttavia, possono avere difficoltà con le **dipendenze a lungo raggio a causa di problemi come i gradienti evanescenti**.

Per affrontare questo problema, sono state sviluppate architetture specializzate come Long Short-Term Memory (LSTM) e Gated Recurrent Unit (GRU). Queste architetture introducono meccanismi di gating che controllano il flusso delle informazioni, permettendo loro di acquisire le dipendenze a lungo raggio in modo più efficace.

- **LSTM**: le reti LSTM utilizzano tre gate (input gate, forget gate e output gate) per regolare il flusso delle informazioni dentro e fuori dallo stato della cella, permettendo loro di ricordare o dimenticare le informazioni su sequenze lunghe. L'input gate controlla quante nuove informazioni aggiungere in base all'input e allo stato nascosto precedente, mentre il forget gate controlla quante informazioni scartare. Combinando l'input gate e il forget gate otteniamo il nuovo stato. Infine, combinando il nuovo stato della cella con l'input e lo stato nascosto precedente otteniamo anche il nuovo stato nascosto.
- **GRU**: le reti GRU semplificano l'architettura LSTM combinando gli input gate e forget gate in un singolo update gate, rendendole computazionalmente più efficienti pur mantenendo la capacità di acquisire le dipendenze a lungo raggio.

## LLM (Large Language Models)

I Large Language Models (LLM) sono un tipo di modello di deep learning progettato specificamente per le attività di elaborazione del linguaggio naturale. Vengono addestrati su enormi quantità di dati testuali e possono generare testo simile a quello umano, rispondere a domande, tradurre lingue ed eseguire diverse altre attività legate al linguaggio.
Gli LLM si basano generalmente su architetture transformer, che utilizzano meccanismi di self-attention per acquisire le relazioni tra le parole in una sequenza, permettendo loro di comprendere il contesto e generare testo coerente.

### Architettura Transformer <sup>[[4]](#references)</sup>
L'architettura transformer è alla base di molti LLM. È costituita da una struttura encoder-decoder, in cui l'encoder elabora la sequenza di input e il decoder genera la sequenza di output. I componenti chiave dell'architettura transformer includono:
- **Meccanismo di Self-Attention**: questo meccanismo permette al modello di ponderare l'importanza delle diverse parole in una sequenza durante la generazione delle rappresentazioni. Calcola gli attention score in base alle relazioni tra le parole, consentendo al modello di concentrarsi sul contesto rilevante.
- **Multi-Head Attention**: questo componente permette al modello di acquisire molteplici relazioni tra le parole utilizzando più attention head, ognuna delle quali si concentra su aspetti diversi dell'input.
- **Codifica posizionale**: poiché i transformer non hanno una nozione integrata dell'ordine delle parole, la codifica posizionale viene aggiunta agli embedding di input per fornire informazioni sulla posizione delle parole nella sequenza.

## Modelli di diffusione <sup>[[5]](#references)</sup>
I modelli di diffusione sono una classe di modelli generativi che imparano a generare dati simulando un processo di diffusione. Sono particolarmente efficaci per attività come la generazione di immagini e hanno acquisito popolarità negli ultimi anni.
I modelli di diffusione funzionano trasformando gradualmente una semplice distribuzione di rumore in una distribuzione complessa di dati attraverso una serie di diffusion step. I componenti chiave dei modelli di diffusione includono:
- **Processo di diffusione forward**: questo processo aggiunge gradualmente rumore ai dati, trasformandoli in una semplice distribuzione di rumore. Il processo di diffusione forward è generalmente definito da una serie di livelli di rumore, in cui ogni livello corrisponde a una quantità specifica di rumore aggiunta ai dati.
- **Processo di diffusione reverse**: questo processo impara a invertire il processo di diffusione forward, eliminando gradualmente il rumore dai dati per generare campioni dalla distribuzione target. Il processo di diffusione reverse viene addestrato utilizzando una loss function che incoraggia il modello a ricostruire i dati originali a partire da campioni rumorosi.

Inoltre, per generare un'immagine da un text prompt, i modelli di diffusione seguono generalmente questi passaggi:
1. **Codifica del testo**: il text prompt viene codificato in una rappresentazione latente utilizzando un text encoder (ad esempio, un modello basato su transformer). Questa rappresentazione acquisisce il significato semantico del testo.
2. **Campionamento del rumore**: un vettore di rumore casuale viene campionato da una distribuzione gaussiana.
3. **Diffusion step**: il modello applica una serie di diffusion step, trasformando gradualmente il vettore di rumore in un'immagine corrispondente al text prompt. Ogni passaggio comporta l'applicazione di trasformazioni apprese per eliminare il rumore dall'immagine.

## References

- [1] [PyTorch - Tutorial sulle reti neurali](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Modelli di diffusione probabilistica per la rimozione del rumore](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
