# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning

Kujifunza kwa kina ni sehemu ya kujifunza mashine inayotumia mitandao ya neva yenye tabaka nyingi (mitandao ya neva ya kina) ili kuunda mifano ya mifumo tata katika data. Imefanikiwa kwa kiwango kikubwa katika maeneo mbalimbali, ikiwa ni pamoja na maono ya kompyuta, usindikaji wa lugha asilia, na utambuzi wa sauti.

### Neural Networks

Mitandao ya neva ndiyo vipengele vya msingi vya kujifunza kwa kina. Inajumuisha nodi zilizounganishwa (neva) zilizopangwa katika tabaka. Kila neva hupokea ingizo, inatumia jumla yenye uzito, na inapita matokeo kupitia kazi ya uhamasishaji ili kutoa matokeo. Tabaka zinaweza kugawanywa kama ifuatavyo:
- **Input Layer**: Tabaka la kwanza linalopokea data ya ingizo.
- **Hidden Layers**: Tabaka za kati zinazofanya mabadiliko kwenye data ya ingizo. Idadi ya tabaka zilizofichwa na neva katika kila tabaka inaweza kutofautiana, na kusababisha usanifu tofauti.
- **Output Layer**: Tabaka ya mwisho inayozalisha matokeo ya mtandao, kama vile uwezekano wa darasa katika kazi za uainishaji.

### Activation Functions

Wakati tabaka la neva linaposhughulikia data ya ingizo, kila neva inatumia uzito na bias kwa ingizo (`z = w * x + b`), ambapo `w` ni uzito, `x` ni ingizo, na `b` ni bias. Matokeo ya neva yanapitishwa kupitia **kazi ya uhamasishaji ili kuingiza usio wa moja kwa moja** katika mfano. Kazi hii ya uhamasishaji kimsingi inaonyesha kama neva inayofuata "inapaswa kuhamasishwa na kiasi gani". Hii inaruhusu mtandao kujifunza mifumo tata na uhusiano katika data, na kuuwezesha kukadiria kazi yoyote isiyo na kikomo.

Kwa hivyo, kazi za uhamasishaji zinaingiza usio wa moja kwa moja katika mtandao wa neva, na kuruhusu kujifunza uhusiano tata katika data. Kazi za kawaida za uhamasishaji ni pamoja na:
- **Sigmoid**: Inachora thamani za ingizo kwenye anuwai kati ya 0 na 1, mara nyingi hutumiwa katika uainishaji wa binary.
- **ReLU (Rectified Linear Unit)**: Inatoa ingizo moja kwa moja ikiwa ni chanya; vinginevyo, inatoa sifuri. Inatumika sana kutokana na urahisi wake na ufanisi katika kufundisha mitandao ya kina.
- **Tanh**: Inachora thamani za ingizo kwenye anuwai kati ya -1 na 1, mara nyingi hutumiwa katika tabaka zilizofichwa.
- **Softmax**: Inabadilisha alama za ghafi kuwa uwezekano, mara nyingi hutumiwa katika tabaka ya matokeo kwa uainishaji wa darasa nyingi.

### Backpropagation

Backpropagation ni algorithimu inayotumiwa kufundisha mitandao ya neva kwa kubadilisha uzito wa uhusiano kati ya neva. Inafanya kazi kwa kuhesabu gradient ya kazi ya hasara kuhusiana na kila uzito na kuboresha uzito katika mwelekeo wa kinyume cha gradient ili kupunguza hasara. Hatua zinazohusika katika backpropagation ni:

1. **Forward Pass**: Hesabu matokeo ya mtandao kwa kupitisha ingizo kupitia tabaka na kutumia kazi za uhamasishaji.
2. **Loss Calculation**: Hesabu hasara (kosa) kati ya matokeo yaliyokadiria na lengo halisi kwa kutumia kazi ya hasara (mfano, makosa ya wastani ya mraba kwa urudufu, cross-entropy kwa uainishaji).
3. **Backward Pass**: Hesabu gradient za hasara kuhusiana na kila uzito kwa kutumia sheria ya mnyororo ya hesabu.
4. **Weight Update**: Sasisha uzito kwa kutumia algorithimu ya kuboresha (mfano, stochastic gradient descent, Adam) ili kupunguza hasara.

## Convolutional Neural Networks (CNNs)

Mitandao ya Neva ya Convolutional (CNNs) ni aina maalum ya mtandao wa neva iliyoundwa kwa ajili ya kushughulikia data kama gridi, kama picha. Zinatumika kwa ufanisi katika kazi za maono ya kompyuta kutokana na uwezo wao wa kujifunza hierarchies za nafasi za vipengele.

Vipengele vikuu vya CNNs ni pamoja na:
- **Convolutional Layers**: Zinatumia operesheni za convolution kwenye data ya ingizo kwa kutumia filters zinazoweza kujifunza (kernels) ili kutoa vipengele vya ndani. Kila filter inateleza juu ya ingizo na kuhesabu bidhaa ya dot, ikizalisha ramani ya kipengele.
- **Pooling Layers**: Zinaondoa saizi za ramani za kipengele ili kupunguza vipimo vyao vya nafasi huku zikihifadhi vipengele muhimu. Operesheni za kawaida za pooling ni pamoja na max pooling na average pooling.
- **Fully Connected Layers**: Zinunganisha kila neva katika tabaka moja na kila neva katika tabaka inayofuata, kama mitandao ya neva ya jadi. Tabaka hizi kwa kawaida hutumiwa mwishoni mwa mtandao kwa kazi za uainishaji.

Ndani ya CNN **`Convolutional Layers`**, tunaweza pia kutofautisha kati ya:
- **Initial Convolutional Layer**: Tabaka la kwanza la convolution linaloshughulikia data ya ingizo ghafi (mfano, picha) na ni muhimu kutambua vipengele vya msingi kama vile mipaka na muundo.
- **Intermediate Convolutional Layers**: Tabaka za convolution zinazofuata ambazo zinajenga juu ya vipengele vilivyofundishwa na tabaka ya awali, kuruhusu mtandao kujifunza mifumo na uwakilishi tata zaidi.
- **Final Convolutional Layer**: Tabaka za mwisho za convolution kabla ya tabaka zilizounganishwa kabisa, ambazo zinakamata vipengele vya kiwango cha juu na kuandaa data kwa ajili ya uainishaji.

> [!TIP]
> CNNs ni za ufanisi hasa kwa uainishaji wa picha, ugunduzi wa vitu, na kazi za kugawanya picha kutokana na uwezo wao wa kujifunza hierarchies za nafasi za vipengele katika data kama gridi na kupunguza idadi ya vigezo kupitia kushiriki uzito.
> Aidha, zinafanya kazi vizuri zaidi na data inayounga mkono kanuni ya eneo la kipengele ambapo data jirani (pikseli) zina uwezekano mkubwa wa kuwa na uhusiano kuliko pikseli za mbali, ambayo huenda isiwe hivyo kwa aina nyingine za data kama maandiko.
> Zaidi ya hayo, kumbuka jinsi CNNs zitakuwa na uwezo wa kutambua hata vipengele tata lakini hazitaweza kutumia muktadha wowote wa nafasi, ikimaanisha kwamba kipengele kile kile kilichopatikana katika sehemu tofauti za picha kitakuwa sawa.

### Example defining a CNN

*Hapa utapata maelezo juu ya jinsi ya kufafanua Mtandao wa Neva wa Convolutional (CNN) katika PyTorch unaoanza na kundi la picha za RGB kama dataset ya ukubwa 48x48 na kutumia tabaka za convolutional na maxpool ili kutoa vipengele, ikifuatiwa na tabaka zilizounganishwa kabisa kwa ajili ya uainishaji.*

Hivi ndivyo unaweza kufafanua tabaka 1 la convolutional katika PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Idadi ya channel za ingizo. Katika kesi ya picha za RGB, hii ni 3 (moja kwa kila channel ya rangi). Ikiwa unafanya kazi na picha za grayscale, hii itakuwa 1.

- `out_channels`: Idadi ya channel za matokeo (filters) ambazo tabaka la convolutional litajifunza. Hii ni hyperparameter ambayo unaweza kubadilisha kulingana na usanifu wa mfano wako.

- `kernel_size`: Ukubwa wa filter ya convolutional. Chaguo la kawaida ni 3x3, ambayo inamaanisha filter itashughulikia eneo la 3x3 la picha ya ingizo. Hii ni kama stamp ya rangi ya 3×3×3 inayotumika kuzalisha out_channels kutoka in_channels:
1. Weka stamp hiyo ya 3×3×3 kwenye kona ya juu-kushoto ya cube ya picha.
2. Weka kila uzito kwa pikseli iliyo chini yake, ongeza zote, ongeza bias → unapata nambari moja.
3. Andika nambari hiyo kwenye ramani tupu katika nafasi (0, 0).
4. Teleza stamp hiyo pikseli moja kulia (stride = 1) na rudia hadi ujaze gridi nzima ya 48×48.

- `padding`: Idadi ya pikseli zilizoongezwa kwenye kila upande wa ingizo. Padding husaidia kuhifadhi vipimo vya nafasi vya ingizo, ikiruhusu udhibiti zaidi juu ya ukubwa wa matokeo. Kwa mfano, na kernel ya 3x3 na ingizo la pikseli 48x48, padding ya 1 itahifadhi ukubwa wa matokeo kuwa sawa (48x48) baada ya operesheni ya convolution. Hii ni kwa sababu padding inaongeza mpaka wa pikseli 1 kuzunguka picha ya ingizo, ikiruhusu kernel kuhamasisha juu ya mipaka bila kupunguza vipimo vya nafasi.

Kisha, idadi ya vigezo vinavyoweza kufundishwa katika tabaka hii ni:
- (3x3x3 (ukubwa wa kernel) + 1 (bias)) x 32 (out_channels) = 896 vigezo vinavyoweza kufundishwa.

Kumbuka kwamba Bias (+1) inaongezwa kwa kila kernel inayotumika kwa sababu kazi ya kila tabaka la convolutional ni kujifunza mabadiliko ya moja kwa moja ya ingizo, ambayo inawakilishwa na equation:
```plaintext
Y = f(W * X + b)
```
ambapo `W` ni matrix ya uzito (filta zilizojifunza, 3x3x3 = 27 params), `b` ni vector ya bias ambayo ni +1 kwa kila channel ya output.

Kumbuka kwamba output ya `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` itakuwa tensor yenye umbo `(batch_size, 32, 48, 48)`, kwa sababu 32 ni idadi mpya ya channels zilizozalishwa za ukubwa wa 48x48 pixels.

Kisha, tunaweza kuunganisha tabaka hili la convolution na tabaka lingine la convolution kama: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Ambayo itaongeza: (32x3x3 (ukubwa wa kernel) + 1 (bias)) x 64 (out_channels) = 18,496 parameters zinazoweza kufundishwa na output yenye umbo `(batch_size, 64, 48, 48)`.

Kama unavyoona, **idadi ya parameters inakua haraka na kila tabaka la convolution lililoongezwa**, hasa kadri idadi ya channels za output inavyoongezeka.

Chaguo moja la kudhibiti kiasi cha data kinachotumika ni kutumia **max pooling** baada ya kila tabaka la convolution. Max pooling inapunguza vipimo vya nafasi vya ramani za sifa, ambayo husaidia kupunguza idadi ya parameters na ugumu wa hesabu huku ikihifadhi sifa muhimu.

Inaweza kutangazwa kama: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Hii kimsingi inaonyesha kutumia gridi ya pixels 2x2 na kuchukua thamani ya juu kutoka kila gridi ili kupunguza ukubwa wa ramani ya sifa kwa nusu. Zaidi ya hayo, `stride=2` inamaanisha kwamba operesheni ya pooling itasonga pixels 2 kwa wakati, katika kesi hii, kuzuia overlap yoyote kati ya maeneo ya pooling.

Kwa tabaka hili la pooling, umbo la output baada ya tabaka la kwanza la convolution litakuwa `(batch_size, 64, 24, 24)` baada ya kutumia `self.pool1` kwa output ya `self.conv2`, ikipunguza ukubwa hadi 1/4 ya tabaka la awali.

> [!TIP]
> Ni muhimu kufanya pooling baada ya tabaka za convolution ili kupunguza vipimo vya nafasi vya ramani za sifa, ambayo husaidia kudhibiti idadi ya parameters na ugumu wa hesabu huku ikifanya parameter ya awali kujifunza sifa muhimu.
> Unaweza kuona convolutions kabla ya tabaka la pooling kama njia ya kutoa sifa kutoka kwa data ya ingizo (kama mistari, mipaka), taarifa hii bado itakuwepo katika output iliyopool, lakini tabaka la convolution linalofuata haliwezi kuona data ya ingizo ya awali, bali tu output iliyopool, ambayo ni toleo lililopunguzwa la tabaka la awali lenye taarifa hiyo.
> Katika mpangilio wa kawaida: `Conv → ReLU → Pool` kila dirisha la pooling la 2×2 sasa linashindana na uanzishaji wa sifa (“mipaka ipo / haipo”), si nguvu za pixel za asili. Kuhifadhi uanzishaji wenye nguvu zaidi kweli kunahifadhi ushahidi muhimu zaidi.

Kisha, baada ya kuongeza tabaka nyingi za convolution na pooling kadri inavyohitajika, tunaweza kulainisha output ili kuipatia tabaka zilizounganishwa kikamilifu. Hii inafanywa kwa kubadilisha tensor kuwa vector ya 1D kwa kila sampuli katika kundi:
```python
x = x.view(-1, 64*24*24)
```
Na kwa hii 1D vector yenye vigezo vyote vya mafunzo vilivyoundwa na tabaka za convolutional na pooling zilizopita, tunaweza kufafanua tabaka lililounganishwa kikamilifu kama:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Ambayo itachukua matokeo yaliyosafishwa ya safu ya awali na kuyapanga kwa vitengo 512 vilivyofichwa.

Tazama jinsi safu hii ilivyoongeza `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` vigezo vinavyoweza kufundishwa, ambavyo ni ongezeko kubwa ikilinganishwa na safu za convolutional. Hii ni kwa sababu safu zilizounganishwa kikamilifu zinawunganisha kila neuron katika safu moja na kila neuron katika safu inayofuata, na kusababisha idadi kubwa ya vigezo.

Hatimaye, tunaweza kuongeza safu ya matokeo ili kuzalisha logits za mwisho za darasa:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Hii itongeza `(512 + 1 (bias)) * num_classes` vigezo vinavyoweza kufundishwa, ambapo `num_classes` ni idadi ya madarasa katika kazi ya uainishaji (kwa mfano, 43 kwa seti ya data ya GTSRB).

Njia nyingine ya kawaida ni kuongeza safu ya dropout kabla ya safu zilizounganishwa kikamilifu ili kuzuia overfitting. Hii inaweza kufanywa kwa:
```python
self.dropout = nn.Dropout(0.5)
```
Hii tabaka kwa bahati huweka sehemu ya vitengo vya ingizo kuwa sifuri wakati wa mafunzo, ambayo husaidia kuzuia overfitting kwa kupunguza utegemezi kwenye neuroni maalum.

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

Msimu ufuatao utaunda baadhi ya data za mafunzo na kufundisha modeli ya `MY_NET` iliyofafanuliwa hapo juu. Baadhi ya thamani za kuvutia za kuzingatia:

- `EPOCHS` ni idadi ya nyakati ambazo modeli itaona seti nzima ya data wakati wa mafunzo. Ikiwa EPOCH ni ndogo sana, modeli inaweza isijifunze vya kutosha; ikiwa ni kubwa sana, inaweza kuathiriwa kupita kiasi.
- `LEARNING_RATE` ni ukubwa wa hatua kwa ajili ya mboreshaji. Kiwango kidogo cha kujifunza kinaweza kusababisha mkusanyiko wa polepole, wakati kiwango kikubwa kinaweza kupita suluhisho bora na kuzuia mkusanyiko.
- `WEIGHT_DECAY` ni neno la kawaida linalosaidia kuzuia kuathiriwa kupita kiasi kwa kuadhibu uzito mkubwa.

Kuhusu mzunguko wa mafunzo, hii ni baadhi ya taarifa za kuvutia kujua:
- `criterion = nn.CrossEntropyLoss()` ni kazi ya hasara inayotumika kwa kazi za uainishaji wa madaraja mengi. Inachanganya uhamasishaji wa softmax na hasara ya msalaba katika kazi moja, na kuifanya iweze kutumika kwa mafunzo ya mifano inayotoa logiti za daraja.
- Ikiwa modeli ilitarajiwa kutoa aina nyingine za matokeo, kama vile uainishaji wa binary au urejeleaji, tungetumia kazi tofauti za hasara kama `nn.BCEWithLogitsLoss()` kwa uainishaji wa binary au `nn.MSELoss()` kwa urejeleaji.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inaanzisha mboreshaji wa Adam, ambao ni chaguo maarufu kwa mafunzo ya mifano ya kujifunza kwa kina. Inabadilisha kiwango cha kujifunza kwa kila parameter kulingana na nyakati za kwanza na pili za gradient.
- Mboreshaji wengine kama `optim.SGD` (Stochastic Gradient Descent) au `optim.RMSprop` pia wanaweza kutumika, kulingana na mahitaji maalum ya kazi ya mafunzo.
- Njia ya `model.train()` inaweka modeli katika hali ya mafunzo, ikiruhusu tabaka kama dropout na batch normalization kutenda tofauti wakati wa mafunzo ikilinganishwa na tathmini.
- `optimizer.zero_grad()` inafuta gradient za tensors zote zilizoboreshwa kabla ya kupita nyuma, ambayo ni muhimu kwa sababu gradient hukusanywa kwa default katika PyTorch. Ikiwa hazifutwa, gradient kutoka kwa mizunguko ya awali zitaongezwa kwa gradient za sasa, na kusababisha sasisho zisizo sahihi.
- `loss.backward()` inahesabu gradient za hasara kuhusiana na vigezo vya modeli, ambavyo vinatumika na mboreshaji kuboresha uzito.
- `optimizer.step()` inasasisha vigezo vya modeli kulingana na gradient zilizohesabiwa na kiwango cha kujifunza.
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
## Recurrent Neural Networks (RNNs)

Recurrent Neural Networks (RNNs) ni darasa la mitandao ya neva iliyoundwa kwa ajili ya kuchakata data za mfululizo, kama vile mfululizo wa wakati au lugha ya asili. Tofauti na mitandao ya neva ya kawaida ya feedforward, RNNs zina uhusiano unaozunguka nyuma, ikiruhusu kudumisha hali ya siri inayoshika taarifa kuhusu ingizo za awali katika mfululizo.

Vipengele vikuu vya RNNs ni pamoja na:
- **Recurrent Layers**: Tabaka hizi zinachakata mfululizo wa ingizo hatua moja kwa wakati, zikisasisha hali yao ya siri kulingana na ingizo la sasa na hali ya siri ya awali. Hii inaruhusu RNNs kujifunza utegemezi wa muda katika data.
- **Hidden State**: Hali ya siri ni vector inayofupisha taarifa kutoka hatua za zamani. Inasasishwa katika kila hatua ya wakati na inatumika kufanya makadirio kwa ingizo la sasa.
- **Output Layer**: Tabaka la pato linaweza kutoa makadirio ya mwisho kulingana na hali ya siri. Katika kesi nyingi, RNNs zinatumika kwa kazi kama vile uundaji wa lugha, ambapo pato ni usambazaji wa uwezekano juu ya neno linalofuata katika mfululizo.

Kwa mfano, katika mfano wa lugha, RNN inachakata mfululizo wa maneno, kwa mfano, "Paka aliketi juu ya" na inakadiria neno linalofuata kulingana na muktadha uliopewa na maneno ya awali, katika kesi hii, "matt".

### Long Short-Term Memory (LSTM) and Gated Recurrent Unit (GRU)

RNNs ni bora hasa kwa kazi zinazohusisha data za mfululizo, kama vile uundaji wa lugha, tafsiri ya mashine, na utambuzi wa sauti. Hata hivyo, wanaweza kuwa na shida na **utegemezi wa muda mrefu kutokana na matatizo kama vile gradients zinazopotea**.

Ili kushughulikia hili, miundo maalum kama Long Short-Term Memory (LSTM) na Gated Recurrent Unit (GRU) zilianzishwa. Miundo hii inaingiza mekanizimu za milango zinazodhibiti mtiririko wa taarifa, ikiruhusu kushika utegemezi wa muda mrefu kwa ufanisi zaidi.

- **LSTM**: Mitandao ya LSTM hutumia milango mitatu (mlango wa ingizo, mlango wa kusahau, na mlango wa pato) kudhibiti mtiririko wa taarifa ndani na nje ya hali ya seli, ikiwaruhusu kukumbuka au kusahau taarifa juu ya mfululizo mrefu. Mlango wa ingizo unadhibiti ni kiasi gani cha taarifa mpya kinachoongezwa kulingana na ingizo na hali ya siri ya awali, mlango wa kusahau unadhibiti ni kiasi gani cha taarifa kinachotupwa. Kwa kuunganisha mlango wa ingizo na mlango wa kusahau tunapata hali mpya. Hatimaye, kwa kuunganisha hali mpya ya seli, na ingizo na hali ya siri ya awali pia tunapata hali mpya ya siri.
- **GRU**: Mitandao ya GRU inarahisisha muundo wa LSTM kwa kuunganisha milango ya ingizo na kusahau kuwa mlango mmoja wa sasisho, ikifanya kuwa na ufanisi zaidi katika hesabu huku bado ikishika utegemezi wa muda mrefu.

## LLMs (Large Language Models)

Large Language Models (LLMs) ni aina ya mfano wa kujifunza kwa kina iliyoundwa mahsusi kwa ajili ya kazi za usindikaji wa lugha ya asili. Zimefundishwa kwa kiasi kikubwa cha data ya maandiko na zinaweza kuzalisha maandiko yanayofanana na ya binadamu, kujibu maswali, kutafsiri lugha, na kutekeleza kazi mbalimbali zinazohusiana na lugha.
LLMs kwa kawaida zinategemea miundo ya transformer, ambayo inatumia mekanizimu za kujitazama ili kushika uhusiano kati ya maneno katika mfululizo, ikiruhusu kuelewa muktadha na kuzalisha maandiko yanayofanana.

### Transformer Architecture
Muundo wa transformer ni msingi wa LLM nyingi. Unajumuisha muundo wa encoder-decoder, ambapo encoder inachakata mfululizo wa ingizo na decoder inazalisha mfululizo wa pato. Vipengele muhimu vya muundo wa transformer ni pamoja na:
- **Self-Attention Mechanism**: Mekanizimu hii inaruhusu mfano kupima umuhimu wa maneno tofauti katika mfululizo wakati wa kuzalisha uwakilishi. Inahesabu alama za umakini kulingana na uhusiano kati ya maneno, ikiruhusu mfano kuzingatia muktadha muhimu.
- **Multi-Head Attention**: Kipengele hiki kinaruhusu mfano kushika uhusiano mwingi kati ya maneno kwa kutumia vichwa vingi vya umakini, kila kikiwa na lengo tofauti la ingizo.
- **Positional Encoding**: Kwa kuwa transformers hazina dhana ya ndani ya mpangilio wa maneno, encoding ya nafasi inaongezwa kwenye embeddings za ingizo ili kutoa taarifa kuhusu nafasi ya maneno katika mfululizo.

## Diffusion Models
Diffusion models ni darasa la mifano ya kizazi ambayo inajifunza kuzalisha data kwa kuiga mchakato wa diffusion. Ni bora hasa kwa kazi kama vile uzalishaji wa picha na zimepata umaarufu katika miaka ya hivi karibuni.
Diffusion models hufanya kazi kwa kubadilisha taratibu usambazaji wa kelele rahisi kuwa usambazaji wa data tata kupitia mfululizo wa hatua za diffusion. Vipengele muhimu vya diffusion models ni pamoja na:
- **Forward Diffusion Process**: Mchakato huu unazidisha kelele kwenye data, ukibadilisha kuwa usambazaji wa kelele rahisi. Mchakato wa diffusion wa mbele kwa kawaida unafafanuliwa na mfululizo wa viwango vya kelele, ambapo kila kiwango kinahusiana na kiasi maalum cha kelele kilichoongezwa kwenye data.
- **Reverse Diffusion Process**: Mchakato huu unajifunza kubadilisha mchakato wa diffusion wa mbele, ukiondoa kelele kwenye data ili kuzalisha sampuli kutoka kwa usambazaji wa lengo. Mchakato wa diffusion wa nyuma unafundishwa kwa kutumia kazi ya hasara inayohimiza mfano kujenga data ya awali kutoka kwa sampuli zenye kelele.

Zaidi ya hayo, ili kuzalisha picha kutoka kwa kichocheo cha maandiko, diffusion models kwa kawaida hufuata hatua hizi:
1. **Text Encoding**: Kichocheo cha maandiko kinahifadhiwa katika uwakilishi wa latent kwa kutumia encoder ya maandiko (kwa mfano, mfano wa msingi wa transformer). Uwiano huu unashika maana ya kisemantiki ya maandiko.
2. **Noise Sampling**: Vector ya kelele isiyo ya kawaida inachukuliwa kutoka kwa usambazaji wa Gaussian.
3. **Diffusion Steps**: Mfano unatumia mfululizo wa hatua za diffusion, ukibadilisha taratibu vector ya kelele kuwa picha inayolingana na kichocheo cha maandiko. Kila hatua inahusisha kutumia mabadiliko yaliyofundishwa ili kuondoa kelele kwenye picha.

{{#include ../banners/hacktricks-training.md}}
