# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning

Diep leer is 'n substel van masjienleer wat neurale netwerke met meerdere lae (diep neurale netwerke) gebruik om komplekse patrone in data te modelleer. Dit het merkwaardige sukses behaal in verskeie domeine, insluitend rekenaarvisie, natuurlike taalverwerking, en spraakherkenning.

### Neural Networks

Neurale netwerke is die boublokke van diep leer. Hulle bestaan uit onderling verbindde nodes (neurone) wat in lae georganiseer is. Elke neuron ontvang insette, pas 'n gewigte som toe, en stuur die resultaat deur 'n aktiveringsfunksie om 'n uitvoer te produseer. Die lae kan soos volg gekategoriseer word:
- **Input Layer**: Die eerste laag wat die insetdata ontvang.
- **Hidden Layers**: Tussentydse lae wat transformasies op die insetdata uitvoer. Die aantal versteekte lae en neurone in elke laag kan verskil, wat lei tot verskillende argitekture.
- **Output Layer**: Die finale laag wat die uitvoer van die netwerk produseer, soos klas waarskynlikhede in klassifikasietake.

### Activation Functions

Wanneer 'n laag neurone insetdata verwerk, pas elke neuron 'n gewig en 'n vooroordeel op die inset toe (`z = w * x + b`), waar `w` die gewig is, `x` die inset is, en `b` die vooroordeel is. Die uitvoer van die neuron word dan deur 'n **aktiveringsfunksie gestuur om nie-lineariteit** in die model in te voer. Hierdie aktiveringsfunksie dui basies aan of die volgende neuron "geaktiveer moet word en hoeveel". Dit stel die netwerk in staat om komplekse patrone en verhoudings in die data te leer, wat dit in staat stel om enige deurlopende funksie te benader.

Daarom stel aktiveringsfunksies nie-lineariteit in die neurale netwerk in, wat dit toelaat om komplekse verhoudings in die data te leer. Algemene aktiveringsfunksies sluit in:
- **Sigmoid**: Kaart insetwaardes na 'n reeks tussen 0 en 1, dikwels gebruik in binêre klassifikasie.
- **ReLU (Rectified Linear Unit)**: Gee die inset direk uit as dit positief is; anders gee dit nul uit. Dit word wyd gebruik weens sy eenvoud en doeltreffendheid in die opleiding van diep netwerke.
- **Tanh**: Kaart insetwaardes na 'n reeks tussen -1 en 1, dikwels gebruik in versteekte lae.
- **Softmax**: Converteer rou tellings in waarskynlikhede, dikwels gebruik in die uitvoerlaag vir multi-klas klassifikasie.

### Backpropagation

Backpropagation is die algoritme wat gebruik word om neurale netwerke op te lei deur die gewigte van die verbindings tussen neurone aan te pas. Dit werk deur die gradiënt van die verliesfunksie ten opsigte van elke gewig te bereken en die gewigte in die teenoorgestelde rigting van die gradiënt op te dateer om die verlies te minimaliseer. Die stappe wat betrokke is by backpropagation is:

1. **Forward Pass**: Bereken die uitvoer van die netwerk deur die inset deur die lae te stuur en aktiveringsfunksies toe te pas.
2. **Loss Calculation**: Bereken die verlies (fout) tussen die voorspelde uitvoer en die werklike teiken met behulp van 'n verliesfunksie (bv. gemiddelde kwadraatfout vir regressie, kruis-entropie vir klassifikasie).
3. **Backward Pass**: Bereken die gradiënte van die verlies ten opsigte van elke gewig met behulp van die kettingreël van calculus.
4. **Weight Update**: Werk die gewigte op met behulp van 'n optimalisering algoritme (bv. stogastiese gradiënt afdaling, Adam) om die verlies te minimaliseer.

## Convolutional Neural Networks (CNNs)

Convolutional Neural Networks (CNNs) is 'n gespesialiseerde tipe neurale netwerk wat ontwerp is vir die verwerking van roosteragtige data, soos beelde. Hulle is veral effektief in rekenaarvisietake weens hul vermoë om outomaties ruimtelike hiërargieë van kenmerke te leer.

Die hoofkomponente van CNNs sluit in:
- **Convolutional Layers**: Pas konvolusie-operasies op die insetdata toe met behulp van leerbare filters (kernels) om plaaslike kenmerke te onttrek. Elke filter gly oor die inset en bereken 'n dotproduk, wat 'n kenmerkkaart produseer.
- **Pooling Layers**: Verminder die kenmerkkaarte se ruimtelike dimensies terwyl belangrike kenmerke behou word. Algemene pooling operasies sluit maksimum pooling en gemiddelde pooling in.
- **Fully Connected Layers**: Verbind elke neuron in een laag met elke neuron in die volgende laag, soortgelyk aan tradisionele neurale netwerke. Hierdie lae word tipies aan die einde van die netwerk vir klassifikasietake gebruik.

Binne 'n CNN **`Convolutional Layers`**, kan ons ook onderskei tussen:
- **Initial Convolutional Layer**: Die eerste konvolusielaag wat die rou insetdata (bv. 'n beeld) verwerk en nuttig is om basiese kenmerke soos kante en teksture te identifiseer.
- **Intermediate Convolutional Layers**: Volgende konvolusielaag wat voortbou op die kenmerke wat deur die aanvanklike laag geleer is, wat die netwerk toelaat om meer komplekse patrone en verteenwoordigings te leer.
- **Final Convolutional Layer**: Die laaste konvolusielaag voor die volledig verbind lae, wat hoëvlak kenmerke vasvang en die data voorberei vir klassifikasie.

> [!TIP]
> CNNs is veral effektief vir beeldklassifikasie, objekdetectie, en beeldsegmentasie take weens hul vermoë om ruimtelike hiërargieë van kenmerke in roosteragtige data te leer en die aantal parameters deur gewigdeling te verminder.
> Boonop werk hulle beter met data wat die kenmerk lokaliteitsbeginsel ondersteun waar naburige data (pixels) meer waarskynlik verwant is as verre pixels, wat dalk nie die geval is vir ander tipes data soos teks nie.
> Verder, let op hoe CNNs in staat sal wees om selfs komplekse kenmerke te identifiseer, maar nie enige ruimtelike konteks toe te pas nie, wat beteken dat dieselfde kenmerk wat in verskillende dele van die beeld gevind word, dieselfde sal wees.

### Example defining a CNN

*Hier sal jy 'n beskrywing vind oor hoe om 'n Convolutional Neural Network (CNN) in PyTorch te definieer wat begin met 'n bondel RGB-beelde as dataset van grootte 48x48 en konvolusielae en maxpool gebruik om kenmerke te onttrek, gevolg deur volledig verbind lae vir klassifikasie.*

Dit is hoe jy 1 konvolusielaag in PyTorch kan definieer: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Aantal insetkanale. In die geval van RGB-beelde is dit 3 (een vir elke kleurkanaal). As jy met gryskaalbeelde werk, sal dit 1 wees.

- `out_channels`: Aantal uitvoerkanale (filters) wat die konvolusielaag sal leer. Dit is 'n hiperparameter wat jy kan aanpas op grond van jou modelargitektuur.

- `kernel_size`: Grootte van die konvolusiefilter. 'n Algemene keuse is 3x3, wat beteken dat die filter 'n 3x3 gebied van die insetbeeld sal dek. Dit is soos 'n 3×3×3 kleurstempel wat gebruik word om die out_channels van die in_channels te genereer:
1. Plaas daardie 3×3×3 stempel op die boonste linkerhoek van die beeldkubus.
2. Vermenigvuldig elke gewig met die pixel onder dit, voeg hulle almal by, voeg vooroordeel by → jy kry een nommer.
3. Skryf daardie nommer in 'n leë kaart op posisie (0, 0).
4. Gly die stempel een pixel na regs (stride = 1) en herhaal totdat jy 'n hele 48×48 rooster vul.

- `padding`: Aantal pixels wat aan elke kant van die inset bygevoeg word. Padding help om die ruimtelike dimensies van die inset te behou, wat meer beheer oor die uitvoergrootte toelaat. Byvoorbeeld, met 'n 3x3 kern en 'n 48x48 pixel inset, sal padding van 1 die uitvoergrootte dieselfde hou (48x48) na die konvolusie-operasie. Dit is omdat die padding 'n grens van 1 pixel rondom die insetbeeld byvoeg, wat die kern toelaat om oor die kante te gly sonder om die ruimtelike dimensies te verminder.

Dan is die aantal leerbare parameters in hierdie laag:
- (3x3x3 (kern grootte) + 1 (vooroordeel)) x 32 (out_channels) = 896 leerbare parameters.

Let daarop dat 'n Vooroordeel (+1) per kern wat gebruik word, bygevoeg word omdat die funksie van elke konvolusielaag is om 'n lineêre transformasie van die inset te leer, wat verteenwoordig word deur die vergelyking:
```plaintext
Y = f(W * X + b)
```
waar die `W` die gewig matriks is (die geleerde filters, 3x3x3 = 27 params), `b` is die vooroordeel vektor wat +1 is vir elke uitvoer kanaal.

Let daarop dat die uitvoer van `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` 'n tensor van vorm `(batch_size, 32, 48, 48)` sal wees, omdat 32 die nuwe aantal gegenereerde kanale van grootte 48x48 pixels is.

Dan kan ons hierdie konvolusielaag aan 'n ander konvolusielaag koppel soos: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Wat sal byvoeg: (32x3x3 (kern grootte) + 1 (vooroordeel)) x 64 (uitvoer kanale) = 18,496 leerbare parameters en 'n uitvoer van vorm `(batch_size, 64, 48, 48)`.

Soos jy kan sien, **groei die aantal parameters vinnig met elke bykomende konvolusielaag**, veral namate die aantal uitvoer kanale toeneem.

Een opsie om die hoeveelheid data wat gebruik word te beheer, is om **max pooling** na elke konvolusielaag te gebruik. Max pooling verminder die ruimtelike dimensies van die kenmerkkaarte, wat help om die aantal parameters en rekenkundige kompleksiteit te verminder terwyl belangrike kenmerke behou word.

Dit kan verklaar word as: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Dit dui basies aan om 'n rooster van 2x2 pixels te gebruik en die maksimum waarde van elke rooster te neem om die grootte van die kenmerkkaart met die helfte te verminder. Verder beteken `stride=2` dat die pooling operasie 2 pixels op 'n slag sal beweeg, in hierdie geval, wat enige oorvleueling tussen die pooling areas voorkom.

Met hierdie pooling laag, sal die uitvoer vorm na die eerste konvolusielaag `(batch_size, 64, 24, 24)` wees nadat `self.pool1` op die uitvoer van `self.conv2` toegepas is, wat die grootte tot 1/4de van die vorige laag verminder.

> [!TIP]
> Dit is belangrik om te pool na die konvolusielaag om die ruimtelike dimensies van die kenmerkkaarte te verminder, wat help om die aantal parameters en rekenkundige kompleksiteit te beheer terwyl die aanvanklike parameter belangrike kenmerke leer.
> Jy kan die konvolusies voor 'n pooling laag sien as 'n manier om kenmerke uit die invoerdata te onttrek (soos lyne, kante), hierdie inligting sal steeds teenwoordig wees in die gepoolde uitvoer, maar die volgende konvolusielaag sal nie in staat wees om die oorspronklike invoerdata te sien nie, net die gepoolde uitvoer, wat 'n verminderde weergawe van die vorige laag met daardie inligting is.
> In die gewone volgorde: `Conv → ReLU → Pool` elke 2×2 pooling venster stry nou met kenmerk aktiverings (“kant teenwoordig / nie”), nie rou pixel intensiteite nie. Om die sterkste aktivering te behou, hou regtig die mees opvallende bewys.

Dan, nadat ons soveel konvolusie- en poolinglae bygevoeg het as wat nodig is, kan ons die uitvoer platmaak om dit in ten volle verbindingslae te voer. Dit word gedoen deur die tensor na 'n 1D vektor vir elke monster in die bondel te hervorm:
```python
x = x.view(-1, 64*24*24)
```
En met hierdie 1D-vektor met al die opleidingsparameters wat deur die vorige konvolusionele en poel-lae gegenereer is, kan ons 'n ten volle verbindingslaag soos volg definieer:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Wat die platgemaakte uitvoer van die vorige laag sal neem en dit na 512 verborge eenhede sal kaart.

Let op hoe hierdie laag `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` leerbare parameters bygevoeg het, wat 'n beduidende toename is in vergelyking met die konvolusielae. Dit is omdat ten volle verbindingslae elke neuron in een laag aan elke neuron in die volgende laag verbind, wat lei tot 'n groot aantal parameters.

Laastens kan ons 'n uitvoerlaag byvoeg om die finale klas logits te produseer:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Dit sal `(512 + 1 (bias)) * num_classes` opleidingsparameters byvoeg, waar `num_classes` die aantal klasse in die klassifikasietaak is (bv. 43 vir die GTSRB-dataset).

Een ander algemene praktyk is om 'n dropout-laag voor die ten volle verbindingslae by te voeg om oorpassing te voorkom. Dit kan gedoen word met:
```python
self.dropout = nn.Dropout(0.5)
```
Hierdie laag stel eweredig 'n fraksie van die invoereenhede op nul tydens opleiding, wat help om oorpassing te voorkom deur die afhanklikheid van spesifieke neurone te verminder.

### CNN Code voorbeeld
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
### CNN Code opleidingsvoorbeeld

Die volgende kode sal 'n paar opleidingsdata genereer en die `MY_NET` model wat hierbo gedefinieer is, oplei. Sommige interessante waardes om op te let:

- `EPOCHS` is die aantal kere wat die model die hele datastel tydens opleiding sal sien. As EPOCH te klein is, mag die model nie genoeg leer nie; as dit te groot is, mag dit oorpas.
- `LEARNING_RATE` is die stapgrootte vir die optimizer. 'n Klein leerkoers mag lei tot stadige konvergensie, terwyl 'n groot een die optimale oplossing mag oorskiet en konvergensie mag voorkom.
- `WEIGHT_DECAY` is 'n regulariseringsterm wat help om oorpassing te voorkom deur groot gewigte te straf.

Ten opsigte van die opleidingslus is dit 'n paar interessante inligting om te weet:
- Die `criterion = nn.CrossEntropyLoss()` is die verliesfunksie wat gebruik word vir multi-klas klassifikasietake. Dit kombineer softmax aktivering en kruis-entropie verlies in 'n enkele funksie, wat dit geskik maak vir die opleiding van modelle wat klas logits uitset.
- As die model verwag is om ander tipes uitsette te lewer, soos binêre klassifikasie of regressie, sou ons verskillende verliesfunksies soos `nn.BCEWithLogitsLoss()` vir binêre klassifikasie of `nn.MSELoss()` vir regressie gebruik.
- Die `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inisieer die Adam optimizer, wat 'n gewilde keuse is vir die opleiding van diep leer modelle. Dit pas die leerkoers aan vir elke parameter gebaseer op die eerste en tweede oomblikke van die gradiënte.
- Ander optimizers soos `optim.SGD` (Stogastiese Gradiënt Afdaling) of `optim.RMSprop` kan ook gebruik word, afhangende van die spesifieke vereistes van die opleidings taak.
- Die `model.train()` metode stel die model in opleidingsmodus, wat lae soos dropout en batch normalisering in staat stel om anders te werk tydens opleiding in vergelyking met evaluasie.
- `optimizer.zero_grad()` maak die gradiënte van alle geoptimaliseerde tensore skoon voor die agterwaartse pas, wat nodig is omdat gradiënte standaard in PyTorch ophoop. As dit nie skoongemaak word nie, sou gradiënte van vorige iterasies by die huidige gradiënte gevoeg word, wat tot onakkurate opdaterings lei.
- `loss.backward()` bereken die gradiënte van die verlies ten opsigte van die modelparameters, wat dan deur die optimizer gebruik word om die gewigte op te dateer.
- `optimizer.step()` werk die modelparameters op gebaseer op die berekende gradiënte en die leerkoers.
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
## Herhalende Neurale Netwerke (RNNs)

Herhalende Neurale Netwerke (RNNs) is 'n klas neurale netwerke wat ontwerp is om opeenvolgende data te verwerk, soos tydreekse of natuurlike taal. Anders as tradisionele feedforward neurale netwerke, het RNNs verbindings wat op hulself terugloop, wat hulle in staat stel om 'n verborge toestand te handhaaf wat inligting oor vorige insette in die reeks vasvang.

Die hoofkomponente van RNNs sluit in:
- **Herhalende Lae**: Hierdie lae verwerk insetreekse een tydstap op 'n slag, en werk hul verborge toestand op grond van die huidige inset en die vorige verborge toestand by. Dit stel RNNs in staat om tydelike afhanklikhede in die data te leer.
- **Verborge Toestand**: Die verborge toestand is 'n vektor wat die inligting van vorige tydstappe opsom. Dit word by elke tydstap opgedateer en word gebruik om voorspellings vir die huidige inset te maak.
- **Uitsetlaag**: Die uitsetlaag produseer die finale voorspellings op grond van die verborge toestand. In baie gevalle word RNNs gebruik vir take soos taalmodellering, waar die uitset 'n waarskynlikheidsverdeling oor die volgende woord in 'n reeks is.

Byvoorbeeld, in 'n taalmodel verwerk die RNN 'n reeks woorde, byvoorbeeld, "Die kat het op die" en voorspel die volgende woord op grond van die konteks wat deur die vorige woorde verskaf word, in hierdie geval, "mat".

### Lang Korttermyn Geheue (LSTM) en Gated Recurrent Unit (GRU)

RNNs is veral effektief vir take wat opeenvolgende data insluit, soos taalmodellering, masjienvertaling en spraakherkenning. Hulle kan egter sukkel met **langafstand afhanklikhede weens probleme soos vervagende gradiënte**.

Om dit aan te spreek, is gespesialiseerde argitekture soos Lang Korttermyn Geheue (LSTM) en Gated Recurrent Unit (GRU) ontwikkel. Hierdie argitekture stel poortmeganismes in wat die vloei van inligting beheer, wat hulle in staat stel om langafstand afhanklikhede meer effektief vas te vang.

- **LSTM**: LSTM-netwerke gebruik drie poorte (invoerpunt, vergeetpoorte, en uitsetpoorte) om die vloei van inligting in en uit die seltoestand te reguleer, wat hulle in staat stel om inligting oor lang reekse te onthou of te vergeet. Die invoerpunt beheer hoeveel nuwe inligting bygevoeg moet word op grond van die inset en die vorige verborge toestand, die vergeetpoorte beheer hoeveel inligting weggegooi moet word. Deur die invoerpunt en die vergeetpoorte te kombineer, kry ons die nuwe toestand. Laastens, deur die nuwe seltoestand, met die inset en die vorige verborge toestand te kombineer, kry ons ook die nuwe verborge toestand.
- **GRU**: GRU-netwerke vereenvoudig die LSTM-argitektuur deur die invoer- en vergeetpoorte in 'n enkele opdateringspoort te kombineer, wat hulle rekenkundig meer doeltreffend maak terwyl hulle steeds langafstand afhanklikhede vasvang.

## LLMs (Groot Taalmodelle)

Groot Taalmodelle (LLMs) is 'n tipe diep leer model wat spesifiek ontwerp is vir natuurlike taalverwerkings take. Hulle word op groot hoeveelhede teksdata opgelei en kan menslike-agtige teks genereer, vrae beantwoord, tale vertaal, en verskeie ander taalverwante take uitvoer. 
LLMs is tipies gebaseer op transformator-argitekture, wat self-aandag meganismes gebruik om verhoudings tussen woorde in 'n reeks vas te vang, wat hulle in staat stel om konteks te verstaan en samehangende teks te genereer.

### Transformator Argitektuur
Die transformator argitektuur is die grondslag van baie LLMs. Dit bestaan uit 'n kodering-dekodering struktuur, waar die kodering die insetreeks verwerk en die dekodering die uitsetreeks genereer. Die sleutelkomponente van die transformator argitektuur sluit in:
- **Self-Aandag Mekanisme**: Hierdie mekanisme stel die model in staat om die belangrikheid van verskillende woorde in 'n reeks te weeg wanneer dit voorstellings genereer. Dit bereken aandag punte op grond van die verhoudings tussen woorde, wat die model in staat stel om op relevante konteks te fokus.
- **Multi-Kop Aandag**: Hierdie komponent stel die model in staat om verskeie verhoudings tussen woorde vas te vang deur verskeie aandagkoppe te gebruik, wat elk op verskillende aspekte van die inset fokus.
- **Posisionele Kodering**: Aangesien transformators nie 'n ingeboude begrip van woordorde het nie, word posisionele kodering by die insetembeddings gevoeg om inligting oor die posisie van woorde in die reeks te verskaf.

## Diffusie Modelle
Diffusie modelle is 'n klas generatiewe modelle wat leer om data te genereer deur 'n diffusieproses te simuleer. Hulle is veral effektief vir take soos beeldgenerasie en het in onlangse jare gewildheid verwerf. 
Diffusie modelle werk deur geleidelik 'n eenvoudige ruisverdeling in 'n komplekse dataverdeling te transformeer deur 'n reeks diffusie stappe. Die sleutelkomponente van diffusie modelle sluit in:
- **Voorwaartse Diffusie Proses**: Hierdie proses voeg geleidelik ruis by die data, wat dit in 'n eenvoudige ruisverdeling transformeer. Die voorwaartse diffusie proses word tipies gedefinieer deur 'n reeks ruisvlakke, waar elke vlak ooreenstem met 'n spesifieke hoeveelheid ruis wat by die data gevoeg word.
- **Achterwaartse Diffusie Proses**: Hierdie proses leer om die voorwaartse diffusie proses te keer, wat die data geleidelik ontruis om monsters van die teikenverdeling te genereer. Die agterwaartse diffusie proses word opgelei met 'n verliesfunksie wat die model aanmoedig om die oorspronklike data uit ruismonsters te herkonstruer.

Boonop, om 'n beeld uit 'n teksprompt te genereer, volg diffusie modelle tipies hierdie stappe:
1. **Teks Kodering**: Die teksprompt word in 'n latente voorstelling gekodeer met behulp van 'n tekskodering (bv. 'n transformator-gebaseerde model). Hierdie voorstelling vang die semantiese betekenis van die teks vas.
2. **Ruis Monsterneming**: 'n Willekeurige ruisvektor word uit 'n Gaussiese verdeling geneem.
3. **Diffusie Stappe**: Die model pas 'n reeks diffusie stappe toe, wat die ruisvektor geleidelik in 'n beeld transformeer wat ooreenstem met die teksprompt. Elke stap behels die toepassing van geleerde transformasies om die beeld te ontruis.

{{#include ../banners/hacktricks-training.md}}
