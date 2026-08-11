# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning <sup>[[1]](#references)</sup>

Deep learning is 'n subset van machine learning wat neural networks met veelvuldige lae (deep neural networks) gebruik om komplekse patrone in data te modelleer. Dit het merkwaardige sukses in verskeie domeine behaal, insluitend rekenaarvisie, natuurliketaalverwerking en spraakherkenning.

### Neural Networks

Neural networks is die boustene van deep learning. Hulle bestaan uit onderling gekoppelde nodusse (neurone) wat in lae georganiseer is. Elke neuron ontvang insette, pas 'n geweegde som toe en stuur die resultaat deur 'n activation function om 'n uitset te produseer. Die lae kan soos volg gekategoriseer word:
- **Input Layer**: Die eerste laag wat die insetdata ontvang.
- **Hidden Layers**: Intermediêre lae wat transformasies op die insetdata uitvoer. Die aantal hidden layers en neurone in elke laag kan wissel, wat tot verskillende argitekture lei.
- **Output Layer**: Die finale laag wat die uitset van die netwerk produseer, soos klaswaarskynlikhede in classification-take.


### Activation Functions

Wanneer 'n laag neurone insetdata verwerk, pas elke neuron 'n gewig en 'n bias op die inset toe (`z = w * x + b`), waar `w` die gewig is, `x` die inset is en `b` die bias is. Die uitset van die neuron word dan deur 'n **activation function gestuur om nie-lineariteit** in die model in te voer. Hierdie activation function dui basies aan of die volgende neuron "geaktiveer moet word en in watter mate". Dit laat die netwerk toe om komplekse patrone en verwantskappe in die data te leer, waardeur dit enige kontinue funksie kan benader.

Activation functions voer dus nie-lineariteit in die neural network in, wat dit toelaat om komplekse verwantskappe in die data te leer. Algemene activation functions sluit in:
- **Sigmoid**: Koppel insetwaardes aan 'n reeks tussen 0 en 1, en word dikwels in binary classification gebruik.
- **ReLU (Rectified Linear Unit)**: Lewer die inset direk as dit positief is; anders lewer dit nul. Dit word wyd gebruik vanweë die eenvoud en doeltreffendheid daarvan tydens die training van deep networks.
- **Tanh**: Koppel insetwaardes aan 'n reeks tussen -1 en 1, en word dikwels in hidden layers gebruik.
- **Softmax**: Skakel rou tellings na waarskynlikhede om, en word dikwels in die output layer vir multi-class classification gebruik.

### Backpropagation

Backpropagation is die algoritme wat gebruik word om neural networks te train deur die gewigte van die verbindings tussen neurone aan te pas. Dit werk deur die gradient van die loss function ten opsigte van elke gewig te bereken en die gewigte in die teenoorgestelde rigting van die gradient by te werk om die loss te minimaliseer. Die stappe betrokke by backpropagation is:

1. **Forward Pass**: Bereken die uitset van die netwerk deur die inset deur die lae te stuur en activation functions toe te pas.
2. **Loss Calculation**: Bereken die loss (fout) tussen die voorspelde uitset en die ware teiken deur 'n loss function te gebruik (bv. mean squared error vir regression, cross-entropy vir classification).
3. **Backward Pass**: Bereken die gradients van die loss ten opsigte van elke gewig deur die kettingreël van calculus te gebruik.
4. **Weight Update**: Werk die gewigte by deur 'n optimization algorithm te gebruik (bv. stochastic gradient descent, Adam) om die loss te minimaliseer.

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Convolutional Neural Networks (CNNs) is 'n gespesialiseerde tipe neural network wat ontwerp is vir die verwerking van roosteragtige data, soos beelde. Hulle is besonder doeltreffend in computer vision-take vanweë hul vermoë om ruimtelike hiërargieë van features outomaties aan te leer.

Die hoofkomponente van CNNs sluit in:
- **Convolutional Layers**: Pas convolution-bewerkings op die insetdata toe deur learnable filters (kernels) te gebruik om plaaslike features te onttrek. Elke filter gly oor die inset en bereken 'n dot product, wat 'n feature map produseer.
- **Pooling Layers**: Verminder die grootte van die feature maps om hul ruimtelike dimensies te verklein terwyl belangrike features behoue bly. Algemene pooling-bewerkings sluit max pooling en average pooling in.
- **Fully Connected Layers**: Verbind elke neuron in een laag met elke neuron in die volgende laag, soortgelyk aan tradisionele neural networks. Hierdie lae word tipies aan die einde van die netwerk vir classification-take gebruik.

Binne 'n CNN se **`Convolutional Layers`** kan ons ook onderskei tussen:
- **Initial Convolutional Layer**: Die eerste convolutional layer wat die rou insetdata (bv. 'n beeld) verwerk en nuttig is om basiese features soos rande en teksture te identifiseer.
- **Intermediate Convolutional Layers**: Daaropvolgende convolutional layers wat voortbou op die features wat deur die aanvanklike laag geleer is, waardeur die netwerk meer komplekse patrone en representasies kan leer.
- **Final Convolutional Layer**: Die laaste convolutional layers voor die fully connected layers, wat hoëvlak-features vaslê en die data vir classification voorberei.

> [!TIP]
> CNNs is besonder doeltreffend vir image classification-, object detection- en image segmentation-take vanweë hul vermoë om ruimtelike hiërargieë van features in roosteragtige data aan te leer en die aantal parameters deur weight sharing te verminder.
> Boonop werk hulle beter met data wat die feature locality-prinsipe ondersteun, waar naburige data (pixels) meer waarskynlik met mekaar verband hou as verafgeleë pixels, wat moontlik nie die geval is vir ander tipes data soos teks nie.
> Let verder daarop dat CNNs selfs komplekse features sal kan identifiseer, maar nie enige ruimtelike konteks sal kan toepas nie; dit beteken dat dieselfde feature wat in verskillende dele van die beeld gevind word, dieselfde sal wees.

### Example defining a CNN

*Hier sal jy 'n beskrywing vind van hoe om 'n Convolutional Neural Network (CNN) in PyTorch te definieer wat met 'n batch RGB-beelde as dataset van grootte 48x48 begin en convolutional layers en maxpool gebruik om features te onttrek, gevolg deur fully connected layers vir classification.*

So kan jy 1 convolutional layer in PyTorch definieer: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Aantal insetkanale. In die geval van RGB-beelde is dit 3 (een vir elke kleurkanaal). As jy met grayscale-beelde werk, sal dit 1 wees.

- `out_channels`: Aantal uitsetkanale (filters) wat die convolutional layer sal leer. Dit is 'n hyperparameter wat jy volgens jou modelargitektuur kan aanpas.

- `kernel_size`: Grootte van die convolutional filter. 'n Algemene keuse is 3x3, wat beteken dat die filter 'n 3x3-area van die insetbeeld sal dek. Dit is soos 'n 3×3×3-kleurstempel wat gebruik word om die out_channels uit die in_channels te genereer:
1. Plaas daardie 3×3×3-stempel op die boonste linkerhoek van die beeldkubus.
2. Vermenigvuldig elke gewig met die pixel daaronder, tel hulle almal bymekaar, tel bias by → jy kry een getal.
3. Skryf daardie getal by posisie (0, 0) in 'n leë kaart.
4. Skuif die stempel een pixel na regs (stride = 1) en herhaal totdat jy 'n volledige 48×48-rooster gevul het.

- `padding`: Aantal pixels wat aan elke kant van die inset gevoeg word. Padding help om die ruimtelike dimensies van die inset te behou, wat meer beheer oor die uitsetgrootte moontlik maak. Byvoorbeeld, met 'n 3x3-kernel en 'n 48x48-pixel-inset sal padding van 1 die uitsetgrootte dieselfde hou (48x48) ná die convolution-bewerking. Dit is omdat die padding 'n rand van 1 pixel rondom die insetbeeld voeg, wat die kernel toelaat om oor die rande te gly sonder om die ruimtelike dimensies te verklein.

Die aantal trainable parameters in hierdie laag is dus:
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 trainable parameters.

Let daarop dat 'n Bias (+1) per gebruikte kernel bygevoeg word, omdat die funksie van elke convolutional layer is om 'n lineêre transformasie van die inset te leer, wat deur die volgende vergelyking voorgestel word:
```plaintext
Y = f(W * X + b)
```
waar die `W` die gewigmatriks is (die geleerde filters, 3x3x3 = 27 parameters), `b` die bias-vektor is wat +1 vir elke output channel is.

Let daarop dat die output van `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` ’n tensor van vorm `(batch_size, 32, 48, 48)` sal wees, omdat 32 die nuwe aantal gegenereerde channels van grootte 48x48 pixels is.

Daarna kan ons hierdie convolutional layer aan ’n ander convolutional layer koppel, soos volg: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Dit sal die volgende byvoeg: (32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 trainable parameters en ’n output van vorm `(batch_size, 64, 48, 48)`.

Soos jy kan sien, **groei die aantal parameters vinnig met elke bykomende convolutional layer**, veral namate die aantal output channels toeneem.

Een opsie om die hoeveelheid data wat gebruik word te beheer, is om **max pooling** ná elke convolutional layer te gebruik. Max pooling verminder die ruimtelike dimensies van die feature maps, wat help om die aantal parameters en computational complexity te verminder terwyl belangrike features behou word.

Dit kan verklaar word as: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Dit dui basies aan dat ’n rooster van 2x2 pixels gebruik moet word en dat die maksimum waarde uit elke rooster geneem moet word om die grootte van die feature map met die helfte te verminder. Verder beteken `stride=2` dat die pooling-operasie 2 pixels op ’n slag sal beweeg; in hierdie geval voorkom dit enige oorvleueling tussen die pooling-areas.

Met hierdie pooling layer sal die output-vorm ná die eerste convolutional layer `(batch_size, 64, 24, 24)` wees nadat `self.pool1` op die output van `self.conv2` toegepas is, wat die grootte tot 1/4 van die vorige layer verminder.

> [!TIP]
> Dit is belangrik om ná die convolutional layers te pool om die ruimtelike dimensies van die feature maps te verminder. Dit help om die aantal parameters en computational complexity te beheer, terwyl dit die aanvanklike parameters laat leer om belangrike features te identifiseer.
>You can see the convolutions before a pooling layer as ’n manier om features uit die input data te onttrek (soos lyne en rande). Hierdie inligting sal steeds in die pooled output teenwoordig wees, maar die volgende convolutional layer sal nie die oorspronklike input data kan sien nie, slegs die pooled output, wat ’n verkleinde weergawe van die vorige layer met daardie inligting is.
>In die gewone volgorde: `Conv → ReLU → Pool` werk elke 2×2 pooling window nou met feature activations (“edge present / not”) eerder as met rou pixelintensiteite. Deur die sterkste activation te behou, word die mees opvallende bewyse inderdaad behou.

Daarna, nadat ons soveel convolutional en pooling layers bygevoeg het as wat nodig is, kan ons die output flatten om dit aan fully connected layers te voer. Dit word gedoen deur die tensor na ’n 1D-vektor vir elke sample in die batch te reshape:
```python
x = x.view(-1, 64*24*24)
```
En met hierdie 1D-vektor met al die opleidingsparameters wat deur die vorige konvolusie- en pooling-lae gegenereer is, kan ons ’n volledig gekoppelde laag soos volg definieer:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Wat die afgeplatte uitvoer van die vorige laag sal neem en dit na 512 hidden units sal karteer.

Let daarop hoe hierdie laag `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` trainable parameters bygevoeg het, wat ’n beduidende toename teenoor die convolutional layers is. Dit is omdat fully connected layers elke neuron in een laag aan elke neuron in die volgende laag koppel, wat tot ’n groot aantal parameters lei.

Laastens kan ons ’n output layer byvoeg om die finale class logits te produseer:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Dit sal `(512 + 1 (bias)) * num_classes` afrigbare parameters byvoeg, waar `num_classes` die aantal klasse in die klassifikasietaak is (bv. 43 vir die GTSRB-datastel).

Een laaste algemene praktyk is om ’n dropout layer voor die fully connected layers by te voeg om overfitting te voorkom. Dit kan soos volg gedoen word:
```python
self.dropout = nn.Dropout(0.5)
```
Hierdie laag stel tydens opleiding lukraak ’n fraksie van die inseteenhede op nul, wat help om oorpassing te voorkom deur die afhanklikheid van spesifieke neurone te verminder.

### CNN Kodevoorbeeld
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
### CNN Code-opleidingsvoorbeeld

Die volgende code sal sommige opleidingsdata skep en die `MY_NET`-model wat hierbo gedefinieer is, oplei. Sommige interessante waardes om op te let:

- `EPOCHS` is die aantal kere wat die model die volledige datastel tydens opleiding sal sien. As EPOCH te klein is, leer die model moontlik nie genoeg nie; as dit te groot is, kan dit oorfit.
- `LEARNING_RATE` is die stapgrootte vir die optimizer. ’n Klein learning rate kan tot stadige konvergensie lei, terwyl ’n groot een die optimale oplossing kan oorskiet en konvergensie kan voorkom.
- `WEIGHT_DECAY` is ’n regularization-term wat help om overfitting te voorkom deur groot gewigte te penaliseer.

Wat die training loop betref, is hier interessante inligting om te ken:
- Die `criterion = nn.CrossEntropyLoss()` is die loss function wat vir multi-class classification-take gebruik word. Dit kombineer softmax-activation en cross-entropy-loss in ’n enkele funksie, wat dit geskik maak vir die opleiding van modelle wat class logits uitvoer.
- As daar van die model verwag word om ander soorte outputs te lewer, soos binary classification of regression, sal ons ander loss functions gebruik, soos `nn.BCEWithLogitsLoss()` vir binary classification of `nn.MSELoss()` vir regression.
- Die `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` initialiseer die Adam optimizer, wat ’n gewilde keuse vir die opleiding van deep learning-modelle is. Dit pas die learning rate vir elke parameter aan gebaseer op die eerste en tweede momente van die gradients.
- Ander optimizers, soos `optim.SGD` (Stochastic Gradient Descent) of `optim.RMSprop`, kan ook gebruik word, afhangend van die spesifieke vereistes van die opleidingstaak.
- Die `model.train()`-metode stel die model in training mode, sodat lae soos dropout en batch normalization tydens opleiding anders as tydens evaluering optree.
- `optimizer.zero_grad()` verwyder die gradients van alle geoptimaliseerde tensors voordat die backward pass uitgevoer word. Dit is nodig omdat gradients by verstek in PyTorch ophoop. Indien dit nie verwyder word nie, sal gradients van vorige iterasies by die huidige gradients gevoeg word, wat tot verkeerde updates lei.
- `loss.backward()` bereken die gradients van die loss ten opsigte van die modelparameters, wat vervolgens deur die optimizer gebruik word om die gewigte by te werk.
- `optimizer.step()` werk die modelparameters by gebaseer op die berekende gradients en die learning rate.
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
## Herhalende neurale netwerke (RNN's) <sup>[[3]](#references)</sup>

Herhalende neurale netwerke (RNN's) is 'n klas neurale netwerke wat ontwerp is vir die verwerking van opeenvolgende data, soos tydreekse of natuurlike taal. Anders as tradisionele feedforward-neurale netwerke, het RNN's verbindings wat na hulself teruglus, sodat hulle 'n versteekte toestand kan behou wat inligting oor vorige insette in die reeks vaslê.

Die hoofkomponente van RNN's sluit in:
- **Herhalende lae**: Hierdie lae verwerk invoerreekse een tydstap op 'n slag en werk hul versteekte toestand by op grond van die huidige invoer en die vorige versteekte toestand. Dit stel RNN's in staat om temporele afhanklikhede in die data aan te leer.
- **Versteekte toestand**: Die versteekte toestand is 'n vektor wat die inligting van vorige tydstappe opsom. Dit word by elke tydstap opgedateer en word gebruik om voorspellings vir die huidige invoer te maak.
- **Uitsetlaag**: Die uitsetlaag lewer die finale voorspellings op grond van die versteekte toestand. In baie gevalle word RNN's gebruik vir take soos taalmodellering, waar die uitset 'n waarskynlikheidsverdeling oor die volgende woord in 'n reeks is.

Byvoorbeeld, in 'n taalmodel verwerk die RNN 'n reeks woorde, byvoorbeeld, "The cat sat on the", en voorspel die volgende woord op grond van die konteks wat deur die vorige woorde verskaf word, in hierdie geval, "mat".

### Long Short-Term Memory (LSTM) en Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

RNN's is besonder doeltreffend vir take wat opeenvolgende data behels, soos taalmodellering, masjienvertaling en spraakherkenning. Hulle kan egter sukkel met **langafstandafhanklikhede weens kwessies soos verdwynnende gradiënte**.

Om dit aan te spreek, is gespesialiseerde argitekture soos Long Short-Term Memory (LSTM) en Gated Recurrent Unit (GRU) ontwikkel. Hierdie argitekture stel hekmeganismes bekend wat die vloei van inligting beheer, sodat hulle langafstandafhanklikhede doeltreffender kan vaslê.

- **LSTM**: LSTM-netwerke gebruik drie hekke (insethek, vergeethek en uitsethek) om die vloei van inligting in en uit die seltoestand te reguleer, wat hulle in staat stel om inligting oor lang reekse heen te onthou of te vergeet. Die insethek beheer hoeveel nuwe inligting bygevoeg moet word op grond van die invoer en die vorige versteekte toestand; die vergeethek beheer hoeveel inligting weggegooi moet word. Deur die insethek en die vergeethek te kombineer, kry ons die nuwe toestand. Laastens kry ons ook die nuwe versteekte toestand deur die nuwe seltoestand met die inset en die vorige versteekte toestand te kombineer.
- **GRU**: GRU-netwerke vereenvoudig die LSTM-argitektuur deur die inset- en vergeethekke in 'n enkele opdateringshek te kombineer, wat hulle rekenaarmatig doeltreffender maak terwyl hulle steeds langafstandafhanklikhede vaslê.

## LLM's (Groottaalmodelle)

Groottaalmodelle (LLM's) is 'n soort deep learning-model wat spesifiek ontwerp is vir natuurliketaalverwerkingstake. Hulle word op groot hoeveelhede teksdata opgelei en kan mensagtige teks genereer, vrae beantwoord, tale vertaal en verskeie ander taalverwante take uitvoer.
LLM's is tipies gebaseer op transformer-argitekture, wat selfaandagmeganismes gebruik om verhoudings tussen woorde in 'n reeks vas te lê, sodat hulle konteks kan verstaan en samehangende teks kan genereer.

### Transformer-argitektuur <sup>[[4]](#references)</sup>
Die transformer-argitektuur is die grondslag van baie LLM's. Dit bestaan uit 'n enkodeerder-dekodeerderstruktuur, waar die enkodeerder die invoerreeks verwerk en die dekodeerder die uitsetreeks genereer. Die belangrikste komponente van die transformer-argitektuur sluit in:
- **Selfaandagmeganisme**: Hierdie meganisme stel die model in staat om die belangrikheid van verskillende woorde in 'n reeks te weeg wanneer representasies gegenereer word. Dit bereken aandagtellings op grond van die verhoudings tussen woorde, sodat die model op relevante konteks kan fokus.
- **Multi-Head Attention**: Hierdie komponent stel die model in staat om veelvuldige verhoudings tussen woorde vas te lê deur verskeie aandagkoppe te gebruik, wat elkeen op verskillende aspekte van die invoer fokus.
- **Posisionele enkodering**: Aangesien transformers nie 'n ingeboude begrip van woordorde het nie, word posisionele enkodering by die invoer-inbeddings gevoeg om inligting oor die posisie van woorde in die reeks te verskaf.

## Diffusiemodelle <sup>[[5]](#references)</sup>
Diffusiemodelle is 'n klas generatiewe modelle wat leer om data te genereer deur 'n diffusi proses te simuleer. Hulle is besonder doeltreffend vir take soos beeldgenerering en het die afgelope jare gewild geword.
Diffusiemodelle werk deur 'n eenvoudige geraasverspreiding geleidelik in 'n komplekse dataverspreiding te omskep deur 'n reeks diffusiestappe. Die belangrikste komponente van diffusiemodelle sluit in:
- **Voorwaartse diffusi proses**: Hierdie proses voeg geleidelik geraas by die data en omskep dit in 'n eenvoudige geraasverspreiding. Die voorwaartse diffusi proses word tipies deur 'n reeks geraasvlakke gedefinieer, waar elke vlak met 'n spesifieke hoeveelheid geraas ooreenstem wat by die data gevoeg word.
- **Omgekeerde diffusi proses**: Hierdie proses leer om die voorwaartse diffusi proses om te keer en die data geleidelik van geraas te ontslae te raak om monsters uit die teikenverspreiding te genereer. Die omgekeerde diffusi proses word opgelei met behulp van 'n verliesfunksie wat die model aanmoedig om die oorspronklike data uit raserige monsters te rekonstrueer.

Daarbenewens volg diffusiemodelle tipies hierdie stappe om 'n beeld uit 'n teksaanwysing te genereer:
1. **Teksenkodering**: Die teksaanwysing word met behulp van 'n teksenkodeerder (bv. 'n transformer-gebaseerde model) in 'n latente representasie geënkodeer. Hierdie representasie vang die semantiese betekenis van die teks vas.
2. **Geraasmonsterneming**: 'n Ewekansige geraasvektor word uit 'n Gaussiese verspreiding gemonster.
3. **Diffusiestappe**: Die model pas 'n reeks diffusiestappe toe en omskep die geraasvektor geleidelik in 'n beeld wat met die teksaanwysing ooreenstem. Elke stap behels die toepassing van aangeleerde transformasies om die geraas uit die beeld te verwyder.

## References

- [1] [PyTorch - Tutoriaal oor neurale netwerke](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Denoising Diffusion Probabilistic Models](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
