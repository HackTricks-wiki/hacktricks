# Duboko učenje

{{#include ../banners/hacktricks-training.md}}

## Duboko učenje <sup>[[1]](#references)</sup>

Duboko učenje je podskup machine learning-a koji koristi neuronske mreže sa više slojeva (duboke neuronske mreže) za modelovanje složenih obrazaca u podacima. Postiglo je izuzetan uspeh u različitim oblastima, uključujući computer vision, natural language processing i prepoznavanje govora.

### Neuronske mreže

Neuronske mreže su osnovni gradivni elementi dubokog učenja. Sastoje se od međusobno povezanih čvorova (neurona) organizovanih u slojeve. Svaki neuron prima ulaze, primenjuje ponderisanu sumu i prosleđuje rezultat kroz activation function kako bi proizveo izlaz. Slojevi se mogu kategorizovati na sledeći način:
- **Input Layer**: Prvi sloj koji prima ulazne podatke.
- **Hidden Layers**: Međuslojevi koji vrše transformacije nad ulaznim podacima. Broj skrivenih slojeva i neurona u svakom sloju može da varira, što dovodi do različitih arhitektura.
- **Output Layer**: Završni sloj koji proizvodi izlaz mreže, kao što su verovatnoće klasa u zadacima klasifikacije.


### Activation Functions

Kada sloj neurona obrađuje ulazne podatke, svaki neuron primenjuje težinu i bias na ulaz (`z = w * x + b`), gde je `w` težina, `x` ulaz, a `b` bias. Izlaz neurona se zatim prosleđuje kroz **activation function kako bi se u model uvela nelinearnost**. Ova activation function u osnovi pokazuje da li sledeći neuron "treba da se aktivira i u kojoj meri". To omogućava mreži da uči složene obrasce i odnose u podacima, čime može da aproksimira bilo koju neprekidnu funkciju.

Dakle, activation functions uvode nelinearnost u neuronsku mrežu, omogućavajući joj da uči složene odnose u podacima. Uobičajene activation functions uključuju:
- **Sigmoid**: Preslikava ulazne vrednosti u opseg između 0 i 1 i često se koristi u binarnoj klasifikaciji.
- **ReLU (Rectified Linear Unit)**: Direktno prosleđuje ulaz ako je pozitivan; u suprotnom prosleđuje nulu. Široko se koristi zbog jednostavnosti i efikasnosti pri obučavanju dubokih mreža.
- **Tanh**: Preslikava ulazne vrednosti u opseg između -1 i 1 i često se koristi u skrivenim slojevima.
- **Softmax**: Pretvara sirove rezultate u verovatnoće i često se koristi u izlaznom sloju za klasifikaciju sa više klasa.

### Backpropagation

Backpropagation je algoritam koji se koristi za obučavanje neuronskih mreža podešavanjem težina veza između neurona. Funkcioniše tako što izračunava gradijent loss function u odnosu na svaku težinu i ažurira težine u suprotnom smeru od gradijenta kako bi se loss smanjio. Koraci uključeni u backpropagation su:

1. **Forward Pass**: Izračunavanje izlaza mreže prosleđivanjem ulaza kroz slojeve i primenom activation functions.
2. **Loss Calculation**: Izračunavanje loss-a (greške) između predviđenog izlaza i stvarne ciljne vrednosti pomoću loss function (npr. srednja kvadratna greška za regresiju, cross-entropy za klasifikaciju).
3. **Backward Pass**: Izračunavanje gradijenata loss-a u odnosu na svaku težinu pomoću chain rule-a iz diferencijalnog računa.
4. **Weight Update**: Ažuriranje težina pomoću optimization algorithm-a (npr. stochastic gradient descent, Adam) kako bi se loss smanjio.

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Convolutional Neural Networks (CNNs) su specijalizovana vrsta neuronskih mreža namenjena obradi podataka organizovanih u obliku mreže, kao što su slike. Posebno su efikasne u zadacima computer vision-a zbog sposobnosti da automatski uče prostorne hijerarhije osobina.

Glavne komponente CNNs uključuju:
- **Convolutional Layers**: Primenjuju convolution operacije nad ulaznim podacima pomoću filtera koji se mogu naučiti (kernels) kako bi izdvojili lokalne osobine. Svaki filter klizi preko ulaza i izračunava dot product, proizvodeći feature map.
- **Pooling Layers**: Smanjuju uzorkovanje feature maps kako bi se smanjile njihove prostorne dimenzije, uz zadržavanje važnih osobina. Uobičajene pooling operacije uključuju max pooling i average pooling.
- **Fully Connected Layers**: Povezuju svaki neuron u jednom sloju sa svakim neuronom u sledećem sloju, slično tradicionalnim neuronskim mrežama. Ovi slojevi se obično koriste na kraju mreže za zadatke klasifikacije.

Unutar CNN **`Convolutional Layers`**, možemo takođe razlikovati:
- **Initial Convolutional Layer**: Prvi convolutional layer koji obrađuje sirove ulazne podatke (npr. sliku) i koristan je za identifikovanje osnovnih osobina kao što su ivice i teksture.
- **Intermediate Convolutional Layers**: Naredni convolutional layers koji nadograđuju osobine naučene u početnom sloju, omogućavajući mreži da uči složenije obrasce i reprezentacije.
- **Final Convolutional Layer**: Poslednji convolutional layers pre fully connected layers, koji beleži osobine visokog nivoa i priprema podatke za klasifikaciju.

> [!TIP]
> CNNs su posebno efikasne za klasifikaciju slika, detekciju objekata i segmentaciju slika zbog sposobnosti da uče prostorne hijerarhije osobina u podacima organizovanim u obliku mreže i smanje broj parametara deljenjem težina.
> Osim toga, bolje rade sa podacima koji podržavaju princip lokalnosti osobina, prema kojem je veća verovatnoća da su susedni podaci (pikseli) povezani nego udaljeni pikseli, što možda nije slučaj kod drugih vrsta podataka, kao što je tekst.
> Takođe, imajte na umu da CNNs mogu da identifikuju čak i složene osobine, ali ne mogu da primene prostorni kontekst, što znači da će ista osobina pronađena u različitim delovima slike biti ista.

### Primer definisanja CNN-a

*Ovde ćete pronaći opis načina definisanja Convolutional Neural Network (CNN) u PyTorch-u, koja počinje sa batch-om RGB slika kao dataset-om veličine 48x48 i koristi convolutional layers i maxpool za izdvajanje osobina, nakon čega slede fully connected layers za klasifikaciju.*

Ovako možete definisati 1 convolutional layer u PyTorch-u: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Broj ulaznih kanala. Kod RGB slika to je 3 (po jedan za svaki kanal boje). Ako radite sa grayscale slikama, vrednost bi bila 1.

- `out_channels`: Broj izlaznih kanala (filtera) koje će convolutional layer naučiti. Ovo je hyperparameter koji možete podesiti na osnovu arhitekture svog modela.

- `kernel_size`: Veličina convolutional filtera. Uobičajen izbor je 3x3, što znači da će filter pokrivati oblast veličine 3x3 na ulaznoj slici. Ovo je poput 3×3×3 pečata u boji koji se koristi za generisanje out_channels iz in_channels:
1. Postavite taj 3×3×3 pečat u gornji levi ugao kocke slike.
2. Pomnožite svaku težinu pikselom ispod nje, saberite ih sve i dodajte bias → dobijate jedan broj.
3. Upišite taj broj u praznu mapu na poziciji (0, 0).
4. Pomerite pečat za jedan piksel udesno (stride = 1) i ponavljajte postupak dok ne popunite celu mrežu veličine 48×48.

- `padding`: Broj piksela dodatih svakoj strani ulaza. Padding pomaže u očuvanju prostornih dimenzija ulaza i omogućava bolju kontrolu veličine izlaza. Na primer, kod 3x3 kernela i ulaza veličine 48x48 piksela, padding vrednosti 1 zadržaće istu veličinu izlaza (48x48) nakon convolution operacije. To je zato što padding dodaje ivicu širine 1 piksel oko ulazne slike, omogućavajući kernelu da klizi preko ivica bez smanjenja prostornih dimenzija.

Zatim je broj parametara koji se mogu trenirati u ovom sloju:
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 trainable parameters.

Imajte na umu da se Bias (+1) dodaje za svaki korišćeni kernel, jer je funkcija svakog convolutional layer-a učenje linearne transformacije ulaza, koja je predstavljena jednačinom:
```plaintext
Y = f(W * X + b)
```
gde je `W` matrica težina (naučeni filteri, 3x3x3 = 27 parametara), `b` vektor bias vrednosti, koji iznosi +1 za svaki izlazni kanal.

Imajte na umu da će izlaz funkcije `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` biti tenzor oblika `(batch_size, 32, 48, 48)`, zato što je 32 novi broj generisanih kanala veličine 48x48 piksela.

Zatim možemo povezati ovaj convolutional layer sa drugim convolutional layer-om, na primer: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Ovo će dodati: (32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 trainable parametara i izlaz oblika `(batch_size, 64, 48, 48)`.

Kao što možete videti, **broj parametara brzo raste sa svakim dodatnim convolutional layer-om**, naročito kada se povećava broj izlaznih kanala.

Jedna od opcija za kontrolu količine korišćenih podataka jeste upotreba **max pooling** sloja nakon svakog convolutional layer-a. Max pooling smanjuje prostorne dimenzije feature mapa, čime se smanjuju broj parametara i computational complexity, uz zadržavanje važnih feature-a.

Može se deklarisati kao: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Ovo u osnovi označava korišćenje mreže od 2x2 piksela i uzimanje maksimalne vrednosti iz svake mreže, čime se veličina feature mape smanjuje upola. Štaviše, `stride=2` znači da će se pooling operation pomerati za 2 piksela odjednom, čime se u ovom slučaju sprečava preklapanje pooling regiona.

Sa ovim pooling layer-om, izlazni oblik nakon prvog convolutional layer-a bio bi `(batch_size, 64, 24, 24)` nakon primene `self.pool1` na izlaz funkcije `self.conv2`, čime se veličina smanjuje na 1/4 prethodnog layer-a.

> [!TIP]
> Važno je primeniti pooling nakon convolutional layer-a kako bi se smanjile prostorne dimenzije feature mapa, što pomaže u kontroli broja parametara i computational complexity, istovremeno omogućavajući početnim parametrima da nauče važne feature-e.
>Convolutions pre pooling layer-a možete posmatrati kao način za izdvajanje feature-a iz ulaznih podataka (kao što su linije i ivice). Ove informacije će i dalje biti prisutne u pooled output-u, ali sledeći convolutional layer neće moći da vidi originalne ulazne podatke, već samo pooled output, koji predstavlja smanjenu verziju prethodnog layer-a sa tim informacijama.
>U uobičajenom redosledu: `Conv → ReLU → Pool`, svaki 2×2 pooling window sada obrađuje feature activations („ivica je prisutna / nije prisutna“), a ne sirove intenzitete piksela. Zadržavanje najsnažnije activation zaista zadržava najistaknutiji dokaz.

Zatim, nakon dodavanja onoliko convolutional i pooling layer-a koliko je potrebno, možemo flatten-ovati izlaz kako bismo ga prosledili fully connected layer-ima. To se radi preoblikovanjem tenzora u 1D vektor za svaki uzorak u batch-u:
```python
x = x.view(-1, 64*24*24)
```
I pomoću ovog 1D vektora sa svim parametrima za treniranje generisanim prethodnim convolutional i pooling slojevima možemo definisati fully connected sloj kao:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Koji će uzeti flattenovani izlaz prethodnog sloja i mapirati ga na 512 hidden units.

Primetite kako je ovaj sloj dodao `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` trainable parameters, što predstavlja značajno povećanje u poređenju sa convolutional layers. To je zato što fully connected layers povezuju svaki neuron u jednom sloju sa svakim neuronom u sledećem sloju, što dovodi do velikog broja parameters.

Na kraju možemo dodati output layer za generisanje konačnih class logits:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Ovo će dodati `(512 + 1 (bias)) * num_classes` parametara koji se mogu trenirati, gde je `num_classes` broj klasa u zadatku klasifikacije (npr. 43 za GTSRB skup podataka).

Još jedna uobičajena praksa je dodavanje dropout sloja pre potpuno povezanih slojeva kako bi se sprečio overfitting. To se može uraditi pomoću:
```python
self.dropout = nn.Dropout(0.5)
```
Ovaj sloj nasumično postavlja deo ulaznih jedinica na nulu tokom obučavanja, što pomaže u sprečavanju overfitting-a smanjenjem oslanjanja na određene neurone.

### Primer koda za CNN
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
### Primer obuke CNN koda

Sledeći kod će kreirati podatke za obuku i obučiti model `MY_NET` definisan iznad. Neke zanimljive vrednosti koje treba imati na umu:

- `EPOCHS` predstavlja broj puta koliko će model videti čitav skup podataka tokom obuke. Ako je EPOCH premali, model možda neće dovoljno naučiti; ako je prevelik, može doći do overfitting-a.
- `LEARNING_RATE` predstavlja veličinu koraka za optimizer. Mala stopa učenja može dovesti do spore konvergencije, dok velika može preskočiti optimalno rešenje i sprečiti konvergenciju.
- `WEIGHT_DECAY` je termin regularizacije koji pomaže u sprečavanju overfitting-a kažnjavanjem velikih težina.

Što se tiče training loop-a, evo nekoliko zanimljivih informacija:
- `criterion = nn.CrossEntropyLoss()` je loss funkcija koja se koristi za multi-class classification zadatke. Ona kombinuje softmax aktivaciju i cross-entropy loss u jednoj funkciji, što je čini pogodnom za obuku modela koji daju class logits.
- Ako se očekivalo da model daje druge vrste izlaza, kao što su binary classification ili regression, koristili bismo različite loss funkcije, kao što je `nn.BCEWithLogitsLoss()` za binary classification ili `nn.MSELoss()` za regression.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inicijalizuje Adam optimizer, koji je popularan izbor za obuku deep learning modela. On prilagođava stopu učenja za svaki parametar na osnovu prvog i drugog momenta gradients-a.
- Mogli bi se koristiti i drugi optimizatori, kao što su `optim.SGD` (Stochastic Gradient Descent) ili `optim.RMSprop`, u zavisnosti od konkretnih zahteva training zadatka.
- Metoda `model.train()` postavlja model u training mode, omogućavajući da se slojevi poput dropout-a i batch normalization-a ponašaju drugačije tokom obuke u odnosu na evaluaciju.
- `optimizer.zero_grad()` briše gradients svih optimizovanih tensor-a pre backward pass-a, što je neophodno zato što se gradients podrazumevano akumuliraju u PyTorch-u. Ako se ne obrišu, gradients iz prethodnih iteracija bi se dodali trenutnim gradients-ima, što bi dovelo do netačnih ažuriranja.
- `loss.backward()` izračunava gradients loss-a u odnosu na parametre modela, koji se zatim koriste za ažuriranje težina pomoću optimizer-a.
- `optimizer.step()` ažurira parametre modela na osnovu izračunatih gradients-a i stope učenja.
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
## Rekurentne neuronske mreže (RNN) <sup>[[3]](#references)</sup>

Rekurentne neuronske mreže (RNN) su klasa neuronskih mreža osmišljena za obradu sekvencijalnih podataka, kao što su vremenske serije ili prirodni jezik. Za razliku od tradicionalnih neuronskih mreža sa propagacijom unapred, RNN imaju veze koje se vraćaju same na sebe, što im omogućava da održavaju skriveno stanje koje obuhvata informacije o prethodnim ulazima u sekvenci.

Glavne komponente RNN mreža uključuju:
- **Rekurentni slojevi**: Ovi slojevi obrađuju ulazne sekvence korak po korak, ažurirajući svoje skriveno stanje na osnovu trenutnog ulaza i prethodnog skrivenog stanja. To omogućava RNN mrežama da uče vremenske zavisnosti u podacima.
- **Skriveno stanje**: Skriveno stanje je vektor koji sažima informacije iz prethodnih vremenskih koraka. Ažurira se pri svakom vremenskom koraku i koristi se za predviđanja na osnovu trenutnog ulaza.
- **Izlazni sloj**: Izlazni sloj proizvodi konačna predviđanja na osnovu skrivenog stanja. U mnogim slučajevima, RNN se koriste za zadatke kao što je jezičko modelovanje, gde je izlaz distribucija verovatnoće nad sledećom rečju u sekvenci.

Na primer, u jezičkom modelu, RNN obrađuje sekvencu reči, na primer, „The cat sat on the“ i predviđa sledeću reč na osnovu konteksta koji pružaju prethodne reči, u ovom slučaju „mat“.

### Long Short-Term Memory (LSTM) i Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

RNN su naročito efikasne za zadatke koji uključuju sekvencijalne podatke, kao što su jezičko modelovanje, mašinsko prevođenje i prepoznavanje govora. Međutim, mogu imati poteškoća sa **zavisnostima velikog dometa zbog problema kao što su nestajući gradijenti**.

Da bi se rešio ovaj problem, razvijene su specijalizovane arhitekture kao što su Long Short-Term Memory (LSTM) i Gated Recurrent Unit (GRU). Ove arhitekture uvode mehanizme gejtovanja koji kontrolišu protok informacija, što im omogućava da efikasnije obuhvate zavisnosti velikog dometa.

- **LSTM**: LSTM mreže koriste tri gejta (ulazni gejt, gejt zaboravljanja i izlazni gejt) za regulisanje protoka informacija u stanje ćelije i iz njega, što im omogućava da pamte ili zaboravljaju informacije tokom dugih sekvenci. Ulazni gejt kontroliše koliko novih informacija treba dodati na osnovu ulaza i prethodnog skrivenog stanja, dok gejt zaboravljanja kontroliše koliko informacija treba odbaciti. Kombinovanjem ulaznog gejta i gejta zaboravljanja dobijamo novo stanje. Konačno, kombinovanjem novog stanja ćelije sa ulazom i prethodnim skrivenim stanjem dobijamo i novo skriveno stanje.
- **GRU**: GRU mreže pojednostavljuju LSTM arhitekturu kombinovanjem ulaznog gejta i gejta zaboravljanja u jedan gejt ažuriranja, čime postaju računski efikasnije, a i dalje obuhvataju zavisnosti velikog dometa.

## LLM (Large Language Models)

Veliki jezički modeli (LLM) su vrsta modela dubokog učenja posebno osmišljena za zadatke obrade prirodnog jezika. Obučavaju se na ogromnim količinama tekstualnih podataka i mogu da generišu tekst nalik ljudskom, odgovaraju na pitanja, prevode jezike i obavljaju različite druge zadatke povezane sa jezikom.
LLM se obično zasnivaju na transformer arhitekturama, koje koriste mehanizme samopažnje za obuhvatanje odnosa između reči u sekvenci, što im omogućava da razumeju kontekst i generišu koherentan tekst.

### Transformer arhitektura <sup>[[4]](#references)</sup>
Transformer arhitektura predstavlja osnovu mnogih LLM modela. Sastoji se od strukture enkodera i dekodera, gde enkoder obrađuje ulaznu sekvencu, a dekoder generiše izlaznu sekvencu. Ključne komponente transformer arhitekture uključuju:
- **Mehanizam samopažnje**: Ovaj mehanizam omogućava modelu da odredi važnost različitih reči u sekvenci prilikom generisanja reprezentacija. Izračunava skorove pažnje na osnovu odnosa između reči, omogućavajući modelu da se usredsredi na relevantan kontekst.
- **Pažnja sa više glava**: Ova komponenta omogućava modelu da obuhvati više odnosa između reči koristeći više glava pažnje, pri čemu se svaka usredsređuje na različite aspekte ulaza.
- **Poziciono kodiranje**: Pošto transformeri nemaju ugrađenu predstavu o redosledu reči, poziciono kodiranje se dodaje ulaznim embedding-ima kako bi se obezbedile informacije o položaju reči u sekvenci.

## Diffusion modeli <sup>[[5]](#references)</sup>
Diffusion modeli su klasa generativnih modela koji uče da generišu podatke simuliranjem diffusion procesa. Posebno su efikasni za zadatke kao što je generisanje slika i stekli su popularnost poslednjih godina.
Diffusion modeli rade tako što postepeno transformišu jednostavnu distribuciju šuma u složenu distribuciju podataka kroz niz diffusion koraka. Ključne komponente diffusion modela uključuju:
- **Proces forward diffusion**: Ovaj proces postepeno dodaje šum podacima, transformišući ih u jednostavnu distribuciju šuma. Proces forward diffusion obično se definiše nizom nivoa šuma, gde svaki nivo odgovara određenoj količini šuma dodatog podacima.
- **Proces reverse diffusion**: Ovaj proces uči da obrne proces forward diffusion, postepeno uklanjajući šum iz podataka kako bi generisao uzorke iz ciljne distribucije. Proces reverse diffusion obučava se pomoću funkcije gubitka koja podstiče model da rekonstruiše originalne podatke iz zašumljenih uzoraka.

Pored toga, za generisanje slike iz tekstualnog prompta, diffusion modeli obično prate sledeće korake:
1. **Kodiranje teksta**: Tekstualni prompt se kodira u latentnu reprezentaciju pomoću enkodera teksta (npr. modela zasnovanog na transformer arhitekturi). Ova reprezentacija obuhvata semantičko značenje teksta.
2. **Uzorkovanje šuma**: Nasumični vektor šuma uzorkuje se iz Gausove distribucije.
3. **Diffusion koraci**: Model primenjuje niz diffusion koraka, postepeno transformišući vektor šuma u sliku koja odgovara tekstualnom promptu. Svaki korak uključuje primenu naučenih transformacija za uklanjanje šuma sa slike.

## References

- [1] [PyTorch - Tutorijal za neuronske mreže](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Denoising Diffusion Probabilistic Models](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
