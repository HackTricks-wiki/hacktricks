# Duboko Učenje

{{#include ../banners/hacktricks-training.md}}

## Duboko Učenje

Duboko učenje je podskup mašinskog učenja koji koristi neuronske mreže sa više slojeva (duboke neuronske mreže) za modelovanje složenih obrazaca u podacima. Postiglo je izvanredan uspeh u raznim domenima, uključujući računarsku viziju, obradu prirodnog jezika i prepoznavanje govora.

### Neuronske Mreže

Neuronske mreže su osnovni gradivni blokovi dubokog učenja. Sastoje se od međusobno povezanih čvorova (neurona) organizovanih u slojeve. Svaki neuron prima ulaze, primenjuje ponderisani zbir i prosleđuje rezultat kroz aktivacionu funkciju da bi proizveo izlaz. Slojevi se mogu kategorizovati na sledeći način:
- **Ulazni Sloj**: Prvi sloj koji prima ulazne podatke.
- **Skriveni Slojevi**: Srednji slojevi koji vrše transformacije na ulaznim podacima. Broj skrivenih slojeva i neurona u svakom sloju može varirati, što dovodi do različitih arhitektura.
- **Izlazni Sloj**: Poslednji sloj koji proizvodi izlaz mreže, kao što su verovatnoće klasa u zadacima klasifikacije.

### Aktivacione Funkcije

Kada sloj neurona obrađuje ulazne podatke, svaki neuron primenjuje težinu i pristrasnost na ulaz (`z = w * x + b`), gde je `w` težina, `x` ulaz, a `b` pristrasnost. Izlaz neurona se zatim prosleđuje kroz **aktivacionu funkciju da bi se u model uvela nelinearnost**. Ova aktivaciona funkcija u suštini označava da li sledeći neuron "treba da bude aktiviran i koliko". Ovo omogućava mreži da uči složene obrasce i odnose u podacima, omogućavajući joj da aproksimira bilo koju kontinuiranu funkciju.

Stoga, aktivacione funkcije uvode nelinearnost u neuronsku mrežu, omogućavajući joj da uči složene odnose u podacima. Uobičajene aktivacione funkcije uključuju:
- **Sigmoid**: Mapira ulazne vrednosti na opseg između 0 i 1, često korišćen u binarnoj klasifikaciji.
- **ReLU (Rectified Linear Unit)**: Izlaz daje direktno ako je pozitivan; u suprotnom, izlaz je nula. Široko se koristi zbog svoje jednostavnosti i efikasnosti u obuci dubokih mreža.
- **Tanh**: Mapira ulazne vrednosti na opseg između -1 i 1, često korišćen u skrivenim slojevima.
- **Softmax**: Konvertuje sirove rezultate u verovatnoće, često korišćen u izlaznom sloju za višeklasnu klasifikaciju.

### Povratna Propagacija

Povratna propagacija je algoritam koji se koristi za obuku neuronskih mreža prilagođavanjem težina veza između neurona. Funkcioniše tako što izračunava gradijent funkcije gubitka u odnosu na svaku težinu i ažurira težine u suprotnom pravcu od gradijenta kako bi minimizovao gubitak. Koraci uključeni u povratnu propagaciju su:

1. **Napredna Prolaz**: Izračunajte izlaz mreže prolazeći ulaz kroz slojeve i primenjujući aktivacione funkcije.
2. **Izračunavanje Gubitka**: Izračunajte gubitak (grešku) između predviđenog izlaza i pravog cilja koristeći funkciju gubitka (npr. srednja kvadratna greška za regresiju, unakrsna entropija za klasifikaciju).
3. **Povratni Prolaz**: Izračunajte gradijente gubitka u odnosu na svaku težinu koristeći pravilo lanca kalkulusa.
4. **Ažuriranje Težina**: Ažurirajte težine koristeći algoritam optimizacije (npr. stohastički gradijentni spust, Adam) kako biste minimizovali gubitak.

## Konvolucione Neuronske Mreže (CNN)

Konvolucione Neuronske Mreže (CNN) su specijalizovana vrsta neuronske mreže dizajnirana za obradu podataka u obliku mreže, kao što su slike. Posebno su efikasne u zadacima računarske vizije zbog svoje sposobnosti da automatski uče prostorne hijerarhije karakteristika.

Glavne komponente CNN uključuju:
- **Konvolucioni Slojevi**: Primena konvolucionih operacija na ulazne podatke koristeći učljive filtre (jezgre) za ekstrakciju lokalnih karakteristika. Svaki filter se pomera preko ulaza i izračunava skalarni proizvod, proizvodeći mapu karakteristika.
- **Slojevi Smanjenja**: Smanjuju mape karakteristika kako bi smanjili njihove prostorne dimenzije dok zadržavaju važne karakteristike. Uobičajene operacije smanjenja uključuju maksimalno smanjenje i prosečno smanjenje.
- **Potpuno Povezani Slojevi**: Povezuju svaki neuron u jednom sloju sa svakim neuronom u sledećem sloju, slično tradicionalnim neuronskim mrežama. Ovi slojevi se obično koriste na kraju mreže za zadatke klasifikacije.

Unutar CNN **`Konvolucioni Slojevi`**, takođe možemo razlikovati između:
- **Početni Konvolucioni Sloj**: Prvi konvolucioni sloj koji obrađuje sirove ulazne podatke (npr. sliku) i koristan je za identifikaciju osnovnih karakteristika kao što su ivice i teksture.
- **Srednji Konvolucioni Slojevi**: Sledeći konvolucioni slojevi koji se oslanjaju na karakteristike naučene od strane početnog sloja, omogućavajući mreži da uči složenije obrasce i reprezentacije.
- **Zadnji Konvolucioni Sloj**: Poslednji konvolucioni slojevi pre potpuno povezanih slojeva, koji hvataju visoko nivoe karakteristika i pripremaju podatke za klasifikaciju.

> [!TIP]
> CNN su posebno efikasni za klasifikaciju slika, prepoznavanje objekata i zadatke segmentacije slika zbog svoje sposobnosti da uče prostorne hijerarhije karakteristika u podacima u obliku mreže i smanje broj parametara kroz deljenje težina.
> Pored toga, bolje funkcionišu sa podacima koji podržavaju princip lokalnosti karakteristika gde su susedni podaci (pikseli) verovatnije povezani nego udaljeni pikseli, što možda nije slučaj za druge vrste podataka kao što je tekst.
> Takođe, imajte na umu kako će CNN moći da identifikuju čak i složene karakteristike, ali neće moći da primene bilo kakav prostorni kontekst, što znači da će ista karakteristika pronađena u različitim delovima slike biti ista.

### Primer definisanja CNN

*Ovde ćete pronaći opis kako definisati Konvolucionu Neuronsku Mrežu (CNN) u PyTorch-u koja počinje sa serijom RGB slika kao skupom podataka veličine 48x48 i koristi konvolucione slojeve i maksimalno smanjenje za ekstrakciju karakteristika, nakon čega slede potpuno povezani slojevi za klasifikaciju.*

Ovako možete definisati 1 konvolucioni sloj u PyTorch-u: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Broj ulaznih kanala. U slučaju RGB slika, to je 3 (jedan za svaki kanal boje). Ako radite sa slikama u nijansama sive, to bi bilo 1.

- `out_channels`: Broj izlaznih kanala (filtri) koje će konvolucioni sloj naučiti. Ovo je hiperparametar koji možete prilagoditi na osnovu arhitekture vašeg modela.

- `kernel_size`: Veličina konvolucionog filtera. Uobičajen izbor je 3x3, što znači da će filter pokriti područje 3x3 ulazne slike. Ovo je poput 3×3×3 pečata boje koji se koristi za generisanje izlaznih kanala iz ulaznih kanala:
1. Postavite taj 3×3×3 pečat u gornji levi ugao kocke slike.
2. Pomnožite svaku težinu sa pikselom ispod njega, saberite ih sve, dodajte pristrasnost → dobijate jedan broj.
3. Zapišite taj broj u praznu mapu na poziciji (0, 0).
4. Pomaknite pečat jedan piksel udesno (korak = 1) i ponovite dok ne popunite celu mrežu 48×48.

- `padding`: Broj piksela dodatih sa svake strane ulaza. Padding pomaže u očuvanju prostornih dimenzija ulaza, omogućavajući veću kontrolu nad veličinom izlaza. Na primer, sa 3x3 jezgrom i ulazom od 48x48 piksela, padding od 1 će zadržati istu veličinu izlaza (48x48) nakon konvolucione operacije. To je zato što padding dodaje granicu od 1 piksela oko ulazne slike, omogućavajući jezgru da se pomera preko ivica bez smanjenja prostornih dimenzija.

Tada je broj parametara koji se mogu obučavati u ovom sloju:
- (3x3x3 (veličina jezgra) + 1 (pristrasnost)) x 32 (izlazni kanali) = 896 parametara koji se mogu obučavati.

Napomena: Pristrasnost (+1) se dodaje po jezgru koje se koristi jer je funkcija svakog konvolucionog sloja da nauči linearne transformacije ulaza, što je predstavljeno jednačinom:
```plaintext
Y = f(W * X + b)
```
gde je `W` matrica težina (naučeni filteri, 3x3x3 = 27 parametara), `b` je vektor pristrasnosti koji je +1 za svaki izlazni kanal.

Napomena da će izlaz `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` biti tenzor oblika `(batch_size, 32, 48, 48)`, jer je 32 novi broj generisanih kanala veličine 48x48 piksela.

Zatim, mogli bismo povezati ovaj konvolucioni sloj sa još jednim konvolucionim slojem kao: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Što će dodati: (32x3x3 (veličina kernela) + 1 (pristrasnost)) x 64 (izlazni kanali) = 18,496 parametara koji se mogu učiti i izlaz oblika `(batch_size, 64, 48, 48)`.

Kao što možete videti, **broj parametara brzo raste sa svakim dodatnim konvolucionim slojem**, posebno kako se povećava broj izlaznih kanala.

Jedna opcija za kontrolu količine korišćenih podataka je korišćenje **max pooling** nakon svakog konvolucionog sloja. Max pooling smanjuje prostorne dimenzije mapa karakteristika, što pomaže u smanjenju broja parametara i računarske složenosti dok zadržava važne karakteristike.

Može se deklarisati kao: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Ovo u suštini označava korišćenje mreže od 2x2 piksela i uzimanje maksimalne vrednosti iz svake mreže kako bi se smanjila veličina mape karakteristika na polovinu. Štaviše, `stride=2` znači da će operacija pooling-a pomerati 2 piksela u isto vreme, u ovom slučaju, sprečavajući bilo kakvo preklapanje između područja pooling-a.

Sa ovim pooling slojem, izlazni oblik nakon prvog konvolucionog sloja biće `(batch_size, 64, 24, 24)` nakon primene `self.pool1` na izlaz `self.conv2`, smanjujući veličinu na 1/4 prethodnog sloja.

> [!TIP]
> Važno je raditi pooling nakon konvolucionih slojeva kako bi se smanjile prostorne dimenzije mapa karakteristika, što pomaže u kontroli broja parametara i računarske složenosti dok inicijalni parametar uči važne karakteristike.
> Možete videti konvolucije pre pooling sloja kao način ekstrakcije karakteristika iz ulaznih podataka (poput linija, ivica), ove informacije će i dalje biti prisutne u pooled izlazu, ali sledeći konvolucioni sloj neće moći da vidi originalne ulazne podatke, samo pooled izlaz, koji je smanjena verzija prethodnog sloja sa tom informacijom.
> U uobičajenom redosledu: `Conv → ReLU → Pool` svaka 2×2 pooling prozorska sada se takmiči sa aktivacijama karakteristika (“ivica prisutna / ne”), a ne sirovim intenzitetima piksela. Održavanje najjače aktivacije zaista čuva najistaknutije dokaze.

Zatim, nakon dodavanja onoliko konvolucionih i pooling slojeva koliko je potrebno, možemo izravnati izlaz kako bismo ga uneli u potpuno povezane slojeve. To se radi preoblikovanjem tenzora u 1D vektor za svaki uzorak u seriji:
```python
x = x.view(-1, 64*24*24)
```
I sa ovim 1D vektorom sa svim parametrima obuke generisanim od prethodnih konvolucijskih i pooling slojeva, možemo definisati potpuno povezani sloj kao:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Koji će uzeti spljošteni izlaz prethodnog sloja i mapirati ga na 512 skrivenih jedinica.

Obratite pažnju na to kako je ovaj sloj dodao `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` parametara koji se mogu trenirati, što je značajan porast u poređenju sa konvolucionim slojevima. To je zato što potpuno povezani slojevi povezuju svaku neuronu u jednom sloju sa svakom neuronom u sledećem sloju, što dovodi do velikog broja parametara.

Na kraju, možemo dodati izlazni sloj da proizvedemo konačne logite klase:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Ovo će dodati `(512 + 1 (bias)) * num_classes` parametara koji se mogu trenirati, gde je `num_classes` broj klasa u zadatku klasifikacije (npr., 43 za GTSRB dataset).

Jedna uobičajena praksa je dodavanje dropout sloja pre potpuno povezanih slojeva kako bi se sprečilo prekomerno prilagođavanje. Ovo se može uraditi sa:
```python
self.dropout = nn.Dropout(0.5)
```
Ova sloj nasumično postavlja deo ulaznih jedinica na nulu tokom obuke, što pomaže u sprečavanju prekomernog prilagođavanja smanjenjem oslanjanja na specifične neurone.

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
### CNN Code training example

Sledeći kod će napraviti neke podatke za obuku i obučiti model `MY_NET` definisan iznad. Neki zanimljivi podaci koje treba napomenuti:

- `EPOCHS` je broj puta kada će model videti ceo skup podataka tokom obuke. Ako je EPOCH previše mali, model možda neće naučiti dovoljno; ako je prevelik, može doći do prekomernog prilagođavanja.
- `LEARNING_RATE` je veličina koraka za optimizator. Mala stopa učenja može dovesti do sporog konvergiranja, dok velika može preći optimalno rešenje i sprečiti konvergenciju.
- `WEIGHT_DECAY` je regularizacioni termin koji pomaže u sprečavanju prekomernog prilagođavanja kažnjavajući velike težine.

Što se tiče petlje obuke, ovo su neke zanimljive informacije koje treba znati:
- `criterion = nn.CrossEntropyLoss()` je funkcija gubitka koja se koristi za zadatke višeklasne klasifikacije. Kombinuje softmax aktivaciju i gubitak unakrsne entropije u jednoj funkciji, što je čini pogodnom za obuku modela koji izlaze sa klasnim logitima.
- Ako se očekivalo da model izlazi sa drugim tipovima izlaza, kao što su binarna klasifikacija ili regresija, koristili bismo različite funkcije gubitka kao što su `nn.BCEWithLogitsLoss()` za binarnu klasifikaciju ili `nn.MSELoss()` za regresiju.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inicijalizuje Adam optimizator, koji je popularan izbor za obuku modela dubokog učenja. Prilagođava stopu učenja za svaki parametar na osnovu prvih i drugih momenata gradijenata.
- Drugi optimizatori kao što su `optim.SGD` (Stohastički gradijentni spust) ili `optim.RMSprop` takođe se mogu koristiti, u zavisnosti od specifičnih zahteva zadatka obuke.
- `model.train()` metoda postavlja model u režim obuke, omogućavajući slojevima kao što su dropout i batch normalizacija da se ponašaju drugačije tokom obuke u poređenju sa evaluacijom.
- `optimizer.zero_grad()` briše gradijente svih optimizovanih tenzora pre unazadnog prolaza, što je neophodno jer se gradijenti po defaultu akumuliraju u PyTorch-u. Ako se ne obrišu, gradijenti iz prethodnih iteracija biće dodati trenutnim gradijentima, što dovodi do netačnih ažuriranja.
- `loss.backward()` izračunava gradijente gubitka u odnosu na parametre modela, koji se zatim koriste od strane optimizatora za ažuriranje težina.
- `optimizer.step()` ažurira parametre modela na osnovu izračunatih gradijenata i stope učenja.
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
## Rekurentne neuronske mreže (RNN)

Rekurentne neuronske mreže (RNN) su klasa neuronskih mreža dizajniranih za obradu sekvencijalnih podataka, kao što su vremenske serije ili prirodni jezik. Za razliku od tradicionalnih feedforward neuronskih mreža, RNN imaju veze koje se vraćaju na sebe, što im omogućava da održavaju skriveno stanje koje hvata informacije o prethodnim ulazima u sekvenci.

Glavne komponente RNN uključuju:
- **Rekurentni slojevi**: Ovi slojevi obrađuju ulazne sekvence jedan vremenski korak u isto vreme, ažurirajući svoje skriveno stanje na osnovu trenutnog ulaza i prethodnog skrivenog stanja. Ovo omogućava RNN da uče vremenske zavisnosti u podacima.
- **Skriveno stanje**: Skriveno stanje je vektor koji sumira informacije iz prethodnih vremenskih koraka. Ažurira se na svakom vremenskom koraku i koristi se za pravljenje predikcija za trenutni ulaz.
- **Izlazni sloj**: Izlazni sloj proizvodi konačne predikcije na osnovu skrivenog stanja. U mnogim slučajevima, RNN se koriste za zadatke poput modelovanja jezika, gde je izlaz verovatnosna distribucija za sledeću reč u sekvenci.

Na primer, u modelu jezika, RNN obrađuje sekvencu reči, na primer, "Mačka je sedela na" i predviđa sledeću reč na osnovu konteksta koji pružaju prethodne reči, u ovom slučaju, "prostirci".

### Duga kratkoročna memorija (LSTM) i Gated Recurrent Unit (GRU)

RNN su posebno efikasne za zadatke koji uključuju sekvencijalne podatke, kao što su modelovanje jezika, mašinsko prevođenje i prepoznavanje govora. Međutim, mogu imati problema sa **dugoročnim zavisnostima zbog problema poput nestajanja gradijenata**.

Da bi se to rešilo, razvijene su specijalizovane arhitekture poput Duga kratkoročna memorija (LSTM) i Gated Recurrent Unit (GRU). Ove arhitekture uvode mehanizme za kontrolu protoka informacija, omogućavajući im da efikasnije hvataju dugoročne zavisnosti.

- **LSTM**: LSTM mreže koriste tri vrata (ulazna vrata, zaboravna vrata i izlazna vrata) za regulisanje protoka informacija unutar i van stanja ćelije, omogućavajući im da pamte ili zaborave informacije tokom dugih sekvenci. Ulazna vrata kontrolišu koliko nove informacije treba dodati na osnovu ulaza i prethodnog skrivenog stanja, zaboravna vrata kontrolišu koliko informacija treba odbaciti. Kombinovanjem ulaznih i zaboravnih vrata dobijamo novo stanje. Na kraju, kombinovanjem novog stanja ćelije sa ulazom i prethodnim skrivenim stanjem dobijamo novo skriveno stanje.
- **GRU**: GRU mreže pojednostavljuju LSTM arhitekturu kombinovanjem ulaznih i zaboravnih vrata u jedna ažurirajuća vrata, čineći ih računski efikasnijim dok i dalje hvataju dugoročne zavisnosti.

## LLMs (Veliki jezički modeli)

Veliki jezički modeli (LLMs) su tip dubokog učenja posebno dizajniran za zadatke obrade prirodnog jezika. Obučeni su na ogromnim količinama tekstualnih podataka i mogu generisati tekst sličan ljudskom, odgovarati na pitanja, prevoditi jezike i obavljati razne druge zadatke vezane za jezik. 
LLMs se obično zasnivaju na transformator arhitekturama, koje koriste mehanizme samopaznje za hvatanje odnosa između reči u sekvenci, omogućavajući im da razumeju kontekst i generišu koherentan tekst.

### Arhitektura transformatora
Arhitektura transformatora je osnova mnogih LLMs. Sastoji se od strukture enkoder-dekoder, gde enkoder obrađuje ulaznu sekvencu, a dekoder generiše izlaznu sekvencu. Ključne komponente arhitekture transformatora uključuju:
- **Mehanizam samopaznje**: Ovaj mehanizam omogućava modelu da proceni važnost različitih reči u sekvenci prilikom generisanja reprezentacija. Izračunava ocene pažnje na osnovu odnosa između reči, omogućavajući modelu da se fokusira na relevantan kontekst.
- **Višekratna pažnja**: Ova komponenta omogućava modelu da hvata više odnosa između reči koristeći više glava pažnje, pri čemu svaka fokusira na različite aspekte ulaza.
- **Poziciono kodiranje**: Pošto transformatori nemaju ugrađenu predstavu o redosledu reči, poziciono kodiranje se dodaje ulaznim ugradnjama kako bi se pružile informacije o poziciji reči u sekvenci.

## Diffusion modeli
Diffusion modeli su klasa generativnih modela koji uče da generišu podatke simulirajući proces difuzije. Posebno su efikasni za zadatke poput generisanja slika i stekli su popularnost u poslednjim godinama. 
Diffusion modeli funkcionišu tako što postepeno transformišu jednostavnu distribuciju šuma u složenu distribuciju podataka kroz niz koraka difuzije. Ključne komponente diffusion modela uključuju:
- **Proces napredne difuzije**: Ovaj proces postepeno dodaje šum podacima, transformišući ih u jednostavnu distribuciju šuma. Proces napredne difuzije se obično definiše nizom nivoa šuma, pri čemu svaki nivo odgovara specifičnoj količini šuma dodatog podacima.
- **Proces obrnute difuzije**: Ovaj proces uči da obrne proces napredne difuzije, postepeno uklanjajući šum iz podataka kako bi generisao uzorke iz ciljne distribucije. Proces obrnute difuzije se obučava koristeći funkciju gubitka koja podstiče model da rekonstruiše originalne podatke iz bučnih uzoraka.

Pored toga, da bi generisali sliku iz tekstualnog upita, diffusion modeli obično prate ove korake:
1. **Kodiranje teksta**: Tekstualni upit se kodira u latentnu reprezentaciju koristeći enkoder teksta (npr. model zasnovan na transformatoru). Ova reprezentacija hvata semantičko značenje teksta.
2. **Uzimanje uzorka šuma**: Nasumični vektor šuma se uzima iz Gaussove distribucije.
3. **Koraci difuzije**: Model primenjuje niz koraka difuzije, postepeno transformišući vektor šuma u sliku koja odgovara tekstualnom upitu. Svaki korak uključuje primenu naučenih transformacija za uklanjanje šuma iz slike.

{{#include ../banners/hacktricks-training.md}}
