# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning

Il deep learning è un sottoinsieme del machine learning che utilizza reti neurali con più strati (reti neurali profonde) per modellare schemi complessi nei dati. Ha raggiunto un successo notevole in vari domini, tra cui visione artificiale, elaborazione del linguaggio naturale e riconoscimento vocale.

### Neural Networks

Le reti neurali sono i mattoni fondamentali del deep learning. Sono costituite da nodi interconnessi (neuroni) organizzati in strati. Ogni neurone riceve input, applica una somma pesata e passa il risultato attraverso una funzione di attivazione per produrre un output. Gli strati possono essere categorizzati come segue:
- **Input Layer**: Il primo strato che riceve i dati di input.
- **Hidden Layers**: Strati intermedi che eseguono trasformazioni sui dati di input. Il numero di strati nascosti e neuroni in ciascuno strato può variare, portando a diverse architetture.
- **Output Layer**: L'ultimo strato che produce l'output della rete, come le probabilità di classe nei compiti di classificazione.

### Activation Functions

Quando uno strato di neuroni elabora i dati di input, ogni neurone applica un peso e un bias all'input (`z = w * x + b`), dove `w` è il peso, `x` è l'input e `b` è il bias. L'output del neurone viene quindi passato attraverso una **funzione di attivazione per introdurre non linearità** nel modello. Questa funzione di attivazione indica fondamentalmente se il neurone successivo "dovrebbe essere attivato e quanto". Questo consente alla rete di apprendere schemi e relazioni complesse nei dati, permettendole di approssimare qualsiasi funzione continua.

Pertanto, le funzioni di attivazione introducono non linearità nella rete neurale, consentendole di apprendere relazioni complesse nei dati. Le funzioni di attivazione comuni includono:
- **Sigmoid**: Mappa i valori di input a un intervallo tra 0 e 1, spesso utilizzato nella classificazione binaria.
- **ReLU (Rectified Linear Unit)**: Restituisce l'input direttamente se è positivo; altrimenti, restituisce zero. È ampiamente utilizzato per la sua semplicità ed efficacia nell'addestramento di reti profonde.
- **Tanh**: Mappa i valori di input a un intervallo tra -1 e 1, spesso utilizzato negli strati nascosti.
- **Softmax**: Converte punteggi grezzi in probabilità, spesso utilizzato nello strato di output per la classificazione multi-classe.

### Backpropagation

La backpropagation è l'algoritmo utilizzato per addestrare le reti neurali regolando i pesi delle connessioni tra i neuroni. Funziona calcolando il gradiente della funzione di perdita rispetto a ciascun peso e aggiornando i pesi nella direzione opposta del gradiente per minimizzare la perdita. I passaggi coinvolti nella backpropagation sono:

1. **Forward Pass**: Calcola l'output della rete passando l'input attraverso gli strati e applicando le funzioni di attivazione.
2. **Loss Calculation**: Calcola la perdita (errore) tra l'output previsto e il vero obiettivo utilizzando una funzione di perdita (ad es., errore quadratico medio per la regressione, entropia incrociata per la classificazione).
3. **Backward Pass**: Calcola i gradienti della perdita rispetto a ciascun peso utilizzando la regola della catena del calcolo.
4. **Weight Update**: Aggiorna i pesi utilizzando un algoritmo di ottimizzazione (ad es., discesa del gradiente stocastica, Adam) per minimizzare la perdita.

## Convolutional Neural Networks (CNNs)

Le Reti Neurali Convoluzionali (CNNs) sono un tipo specializzato di rete neurale progettata per elaborare dati a griglia, come le immagini. Sono particolarmente efficaci nei compiti di visione artificiale grazie alla loro capacità di apprendere automaticamente gerarchie spaziali di caratteristiche.

I principali componenti delle CNN includono:
- **Convolutional Layers**: Applicano operazioni di convoluzione ai dati di input utilizzando filtri (kernel) apprendibili per estrarre caratteristiche locali. Ogni filtro scorre sull'input e calcola un prodotto scalare, producendo una mappa delle caratteristiche.
- **Pooling Layers**: Ridimensionano le mappe delle caratteristiche per ridurre le loro dimensioni spaziali mantenendo caratteristiche importanti. Le operazioni di pooling comuni includono max pooling e average pooling.
- **Fully Connected Layers**: Collegano ogni neurone in uno strato a ogni neurone nello strato successivo, simile alle reti neurali tradizionali. Questi strati sono tipicamente utilizzati alla fine della rete per compiti di classificazione.

All'interno di una CNN **`Convolutional Layers`**, possiamo anche distinguere tra:
- **Initial Convolutional Layer**: Il primo strato convoluzionale che elabora i dati di input grezzi (ad es., un'immagine) ed è utile per identificare caratteristiche di base come bordi e texture.
- **Intermediate Convolutional Layers**: Strati convoluzionali successivi che si basano sulle caratteristiche apprese dallo strato iniziale, consentendo alla rete di apprendere schemi e rappresentazioni più complessi.
- **Final Convolutional Layer**: Gli ultimi strati convoluzionali prima degli strati completamente connessi, che catturano caratteristiche di alto livello e preparano i dati per la classificazione.

> [!TIP]
> Le CNN sono particolarmente efficaci per la classificazione delle immagini, il rilevamento degli oggetti e i compiti di segmentazione delle immagini grazie alla loro capacità di apprendere gerarchie spaziali di caratteristiche nei dati a griglia e ridurre il numero di parametri attraverso la condivisione dei pesi.
> Inoltre, funzionano meglio con dati che supportano il principio della località delle caratteristiche, dove i dati vicini (pixel) sono più propensi a essere correlati rispetto ai pixel distanti, il che potrebbe non essere il caso per altri tipi di dati come il testo.
> Inoltre, nota come le CNN saranno in grado di identificare anche caratteristiche complesse ma non saranno in grado di applicare alcun contesto spaziale, il che significa che la stessa caratteristica trovata in diverse parti dell'immagine sarà la stessa.

### Example defining a CNN

*Qui troverai una descrizione su come definire una Rete Neurale Convoluzionale (CNN) in PyTorch che inizia con un batch di immagini RGB come dataset di dimensione 48x48 e utilizza strati convoluzionali e maxpool per estrarre caratteristiche, seguiti da strati completamente connessi per la classificazione.*

Questo è come puoi definire 1 strato convoluzionale in PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Numero di canali di input. Nel caso di immagini RGB, questo è 3 (uno per ciascun canale di colore). Se stai lavorando con immagini in scala di grigi, questo sarebbe 1.

- `out_channels`: Numero di canali di output (filtri) che lo strato convoluzionale apprenderà. Questo è un iperparametro che puoi regolare in base all'architettura del tuo modello.

- `kernel_size`: Dimensione del filtro convoluzionale. Una scelta comune è 3x3, il che significa che il filtro coprirà un'area di 3x3 dell'immagine di input. Questo è come un timbro colorato 3×3×3 che viene utilizzato per generare gli out_channels dagli in_channels:
1. Posiziona quel timbro 3×3×3 nell'angolo in alto a sinistra del cubo dell'immagine.
2. Moltiplica ogni peso per il pixel sottostante, somma tutto, aggiungi il bias → ottieni un numero.
3. Scrivi quel numero in una mappa vuota nella posizione (0, 0).
4. Scorri il timbro di un pixel a destra (stride = 1) e ripeti fino a riempire un'intera griglia 48×48.

- `padding`: Numero di pixel aggiunti a ciascun lato dell'input. Il padding aiuta a preservare le dimensioni spaziali dell'input, consentendo un maggiore controllo sulla dimensione dell'output. Ad esempio, con un kernel 3x3 e un input di 48x48 pixel, un padding di 1 manterrà la dimensione dell'output la stessa (48x48) dopo l'operazione di convoluzione. Questo perché il padding aggiunge un bordo di 1 pixel attorno all'immagine di input, consentendo al kernel di scorrere sui bordi senza ridurre le dimensioni spaziali.

Quindi, il numero di parametri addestrabili in questo strato è:
- (3x3x3 (dimensione del kernel) + 1 (bias)) x 32 (out_channels) = 896 parametri addestrabili.

Nota che un Bias (+1) è aggiunto per ogni kernel utilizzato perché la funzione di ciascun strato convoluzionale è quella di apprendere una trasformazione lineare dell'input, che è rappresentata dall'equazione:
```plaintext
Y = f(W * X + b)
```
dove `W` è la matrice dei pesi (i filtri appresi, 3x3x3 = 27 parametri), `b` è il vettore di bias che è +1 per ogni canale di output.

Nota che l'output di `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` sarà un tensore di forma `(batch_size, 32, 48, 48)`, perché 32 è il nuovo numero di canali generati di dimensione 48x48 pixel.

Poi, potremmo collegare questo strato convoluzionale a un altro strato convoluzionale come: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Questo aggiungerà: (32x3x3 (dimensione del kernel) + 1 (bias)) x 64 (out_channels) = 18.496 parametri addestrabili e un output di forma `(batch_size, 64, 48, 48)`.

Come puoi vedere, **il numero di parametri cresce rapidamente con ogni ulteriore strato convoluzionale**, specialmente man mano che aumenta il numero di canali di output.

Un'opzione per controllare la quantità di dati utilizzati è usare **max pooling** dopo ogni strato convoluzionale. Il max pooling riduce le dimensioni spaziali delle mappe delle caratteristiche, il che aiuta a ridurre il numero di parametri e la complessità computazionale mantenendo le caratteristiche importanti.

Può essere dichiarato come: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Questo indica fondamentalmente di utilizzare una griglia di 2x2 pixel e prendere il valore massimo da ciascuna griglia per ridurre la dimensione della mappa delle caratteristiche della metà. Inoltre, `stride=2` significa che l'operazione di pooling si sposterà di 2 pixel alla volta, in questo caso, prevenendo qualsiasi sovrapposizione tra le regioni di pooling.

Con questo strato di pooling, la forma dell'output dopo il primo strato convoluzionale sarebbe `(batch_size, 64, 24, 24)` dopo aver applicato `self.pool1` all'output di `self.conv2`, riducendo la dimensione a 1/4 di quella del livello precedente.

> [!TIP]
> È importante fare pooling dopo gli strati convoluzionali per ridurre le dimensioni spaziali delle mappe delle caratteristiche, il che aiuta a controllare il numero di parametri e la complessità computazionale mentre si fa in modo che il parametro iniziale apprenda caratteristiche importanti.
> Puoi vedere le convoluzioni prima di uno strato di pooling come un modo per estrarre caratteristiche dai dati di input (come linee, bordi), queste informazioni saranno ancora presenti nell'output poolato, ma il successivo strato convoluzionale non sarà in grado di vedere i dati di input originali, solo l'output poolato, che è una versione ridotta del livello precedente con quelle informazioni.
> Nell'ordine abituale: `Conv → ReLU → Pool` ogni finestra di pooling 2×2 ora compete con le attivazioni delle caratteristiche (“bordo presente / assente”), non con le intensità dei pixel grezzi. Mantenere l'attivazione più forte mantiene davvero le prove più salienti.

Poi, dopo aver aggiunto quanti più strati convoluzionali e di pooling necessario, possiamo appiattire l'output per alimentarlo in strati completamente connessi. Questo viene fatto rimodellando il tensore in un vettore 1D per ogni campione nel batch:
```python
x = x.view(-1, 64*24*24)
```
E con questo vettore 1D con tutti i parametri di addestramento generati dai precedenti strati convoluzionali e di pooling, possiamo definire uno strato completamente connesso come:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Che prenderà l'output appiattito dello strato precedente e lo mapperà a 512 unità nascoste.

Nota come questo strato abbia aggiunto `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` parametri addestrabili, che è un aumento significativo rispetto agli strati convoluzionali. Questo perché gli strati completamente connessi collegano ogni neurone in uno strato a ogni neurone nello strato successivo, portando a un gran numero di parametri.

Infine, possiamo aggiungere uno strato di output per produrre i logit della classe finale:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Questo aggiungerà `(512 + 1 (bias)) * num_classes` parametri addestrabili, dove `num_classes` è il numero di classi nel compito di classificazione (ad esempio, 43 per il dataset GTSRB).

Una pratica comune è aggiungere uno strato di dropout prima degli strati completamente connessi per prevenire l'overfitting. Questo può essere fatto con:
```python
self.dropout = nn.Dropout(0.5)
```
Questo strato imposta casualmente una frazione delle unità di input a zero durante l'addestramento, il che aiuta a prevenire l'overfitting riducendo la dipendenza da neuroni specifici.

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
### Esempio di codice per l'addestramento CNN

Il seguente codice genererà alcuni dati di addestramento e addestrerà il modello `MY_NET` definito sopra. Alcuni valori interessanti da notare:

- `EPOCHS` è il numero di volte che il modello vedrà l'intero dataset durante l'addestramento. Se EPOCH è troppo piccolo, il modello potrebbe non apprendere abbastanza; se troppo grande, potrebbe sovradattarsi.
- `LEARNING_RATE` è la dimensione del passo per l'ottimizzatore. Un tasso di apprendimento piccolo può portare a una convergenza lenta, mentre uno grande può superare la soluzione ottimale e impedire la convergenza.
- `WEIGHT_DECAY` è un termine di regolarizzazione che aiuta a prevenire il sovradattamento penalizzando i pesi grandi.

Riguardo al ciclo di addestramento, ecco alcune informazioni interessanti da sapere:
- Il `criterion = nn.CrossEntropyLoss()` è la funzione di perdita utilizzata per compiti di classificazione multi-classe. Combina l'attivazione softmax e la perdita di entropia incrociata in un'unica funzione, rendendola adatta per addestrare modelli che producono logit di classe.
- Se ci si aspettava che il modello producesse altri tipi di output, come la classificazione binaria o la regressione, utilizzeremmo funzioni di perdita diverse come `nn.BCEWithLogitsLoss()` per la classificazione binaria o `nn.MSELoss()` per la regressione.
- L'`optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inizializza l'ottimizzatore Adam, che è una scelta popolare per l'addestramento di modelli di deep learning. Adatta il tasso di apprendimento per ogni parametro in base ai primi e secondi momenti dei gradienti.
- Altri ottimizzatori come `optim.SGD` (Stochastic Gradient Descent) o `optim.RMSprop` potrebbero essere utilizzati, a seconda dei requisiti specifici del compito di addestramento.
- Il metodo `model.train()` imposta il modello in modalità di addestramento, consentendo a strati come dropout e normalizzazione del batch di comportarsi in modo diverso durante l'addestramento rispetto alla valutazione.
- `optimizer.zero_grad()` cancella i gradienti di tutti i tensori ottimizzati prima del passaggio all'indietro, il che è necessario perché i gradienti si accumulano per impostazione predefinita in PyTorch. Se non vengono cancellati, i gradienti delle iterazioni precedenti verrebbero aggiunti ai gradienti correnti, portando a aggiornamenti errati.
- `loss.backward()` calcola i gradienti della perdita rispetto ai parametri del modello, che vengono poi utilizzati dall'ottimizzatore per aggiornare i pesi.
- `optimizer.step()` aggiorna i parametri del modello in base ai gradienti calcolati e al tasso di apprendimento.
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
## Reti Neurali Ricorrenti (RNN)

Le Reti Neurali Ricorrenti (RNN) sono una classe di reti neurali progettate per elaborare dati sequenziali, come serie temporali o linguaggio naturale. A differenza delle tradizionali reti neurali feedforward, le RNN hanno connessioni che si riavvolgono su se stesse, permettendo loro di mantenere uno stato nascosto che cattura informazioni sugli input precedenti nella sequenza.

I principali componenti delle RNN includono:
- **Strati Ricorrenti**: Questi strati elaborano le sequenze di input un passo temporale alla volta, aggiornando il loro stato nascosto in base all'input attuale e allo stato nascosto precedente. Questo consente alle RNN di apprendere dipendenze temporali nei dati.
- **Stato Nascosto**: Lo stato nascosto è un vettore che riassume le informazioni dai passi temporali precedenti. Viene aggiornato ad ogni passo temporale ed è utilizzato per fare previsioni sull'input attuale.
- **Strato di Uscita**: Lo strato di uscita produce le previsioni finali basate sullo stato nascosto. In molti casi, le RNN sono utilizzate per compiti come la modellazione del linguaggio, dove l'output è una distribuzione di probabilità sulla prossima parola in una sequenza.

Ad esempio, in un modello di linguaggio, la RNN elabora una sequenza di parole, ad esempio, "Il gatto si è seduto su" e prevede la prossima parola in base al contesto fornito dalle parole precedenti, in questo caso, "tappeto".

### Memoria a Lungo e Breve Termine (LSTM) e Unità Ricorrente Gated (GRU)

Le RNN sono particolarmente efficaci per compiti che coinvolgono dati sequenziali, come la modellazione del linguaggio, la traduzione automatica e il riconoscimento vocale. Tuttavia, possono avere difficoltà con **dipendenze a lungo raggio a causa di problemi come il gradiente che svanisce**.

Per affrontare questo problema, sono state sviluppate architetture specializzate come la Memoria a Lungo e Breve Termine (LSTM) e l'Unità Ricorrente Gated (GRU). Queste architetture introducono meccanismi di gating che controllano il flusso di informazioni, permettendo loro di catturare dipendenze a lungo raggio in modo più efficace.

- **LSTM**: Le reti LSTM utilizzano tre porte (porta di input, porta di dimenticanza e porta di output) per regolare il flusso di informazioni dentro e fuori dallo stato della cella, consentendo loro di ricordare o dimenticare informazioni su lunghe sequenze. La porta di input controlla quanto nuova informazione aggiungere in base all'input e allo stato nascosto precedente, la porta di dimenticanza controlla quanto informazione scartare. Combinando la porta di input e la porta di dimenticanza otteniamo il nuovo stato. Infine, combinando il nuovo stato della cella, con l'input e lo stato nascosto precedente otteniamo anche il nuovo stato nascosto.
- **GRU**: Le reti GRU semplificano l'architettura LSTM combinando le porte di input e di dimenticanza in un'unica porta di aggiornamento, rendendole computazionalmente più efficienti pur catturando ancora dipendenze a lungo raggio.

## LLM (Modelli di Linguaggio di Grandi Dimensioni)

I Modelli di Linguaggio di Grandi Dimensioni (LLM) sono un tipo di modello di deep learning specificamente progettato per compiti di elaborazione del linguaggio naturale. Sono addestrati su enormi quantità di dati testuali e possono generare testo simile a quello umano, rispondere a domande, tradurre lingue e svolgere vari altri compiti legati al linguaggio. 
Gli LLM si basano tipicamente su architetture transformer, che utilizzano meccanismi di autoattenzione per catturare relazioni tra le parole in una sequenza, permettendo loro di comprendere il contesto e generare testo coerente.

### Architettura Transformer
L'architettura transformer è la base di molti LLM. Consiste in una struttura encoder-decoder, dove l'encoder elabora la sequenza di input e il decoder genera la sequenza di output. I componenti chiave dell'architettura transformer includono:
- **Meccanismo di Autoattenzione**: Questo meccanismo consente al modello di pesare l'importanza di diverse parole in una sequenza quando genera rappresentazioni. Calcola punteggi di attenzione basati sulle relazioni tra le parole, consentendo al modello di concentrarsi sul contesto rilevante.
- **Attenzione Multi-Testa**: Questo componente consente al modello di catturare più relazioni tra le parole utilizzando più teste di attenzione, ognuna focalizzata su diversi aspetti dell'input.
- **Codifica Posizionale**: Poiché i transformer non hanno una nozione incorporata dell'ordine delle parole, la codifica posizionale viene aggiunta agli embedding di input per fornire informazioni sulla posizione delle parole nella sequenza.

## Modelli di Diffusione
I modelli di diffusione sono una classe di modelli generativi che apprendono a generare dati simulando un processo di diffusione. Sono particolarmente efficaci per compiti come la generazione di immagini e hanno guadagnato popolarità negli ultimi anni. 
I modelli di diffusione funzionano trasformando gradualmente una semplice distribuzione di rumore in una distribuzione di dati complessa attraverso una serie di passaggi di diffusione. I componenti chiave dei modelli di diffusione includono:
- **Processo di Diffusione Avanzata**: Questo processo aggiunge gradualmente rumore ai dati, trasformandoli in una semplice distribuzione di rumore. Il processo di diffusione avanzata è tipicamente definito da una serie di livelli di rumore, dove ogni livello corrisponde a una specifica quantità di rumore aggiunta ai dati.
- **Processo di Diffusione Inversa**: Questo processo apprende a invertire il processo di diffusione avanzata, denoising gradualmente i dati per generare campioni dalla distribuzione target. Il processo di diffusione inversa viene addestrato utilizzando una funzione di perdita che incoraggia il modello a ricostruire i dati originali da campioni rumorosi.

Inoltre, per generare un'immagine da un prompt testuale, i modelli di diffusione seguono tipicamente questi passaggi:
1. **Codifica del Testo**: Il prompt testuale viene codificato in una rappresentazione latente utilizzando un codificatore di testo (ad esempio, un modello basato su transformer). Questa rappresentazione cattura il significato semantico del testo.
2. **Campionamento del Rumore**: Un vettore di rumore casuale viene campionato da una distribuzione gaussiana.
3. **Passaggi di Diffusione**: Il modello applica una serie di passaggi di diffusione, trasformando gradualmente il vettore di rumore in un'immagine che corrisponde al prompt testuale. Ogni passaggio comporta l'applicazione di trasformazioni apprese per denoising l'immagine.

{{#include ../banners/hacktricks-training.md}}
