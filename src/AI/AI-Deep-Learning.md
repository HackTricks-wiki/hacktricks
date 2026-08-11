# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning <sup>[[1]](#references)</sup>

Deep learning ni sehemu ndogo ya machine learning inayotumia neural networks zenye layers nyingi (deep neural networks) kuiga mifumo changamano katika data. Imefanikiwa kwa kiwango kikubwa katika nyanja mbalimbali, zikiwemo computer vision, natural language processing, na speech recognition.

### Neural Networks

Neural networks ni vipengele vya msingi vya deep learning. Zinajumuisha nodes zilizounganishwa (neurons) zilizopangwa katika layers. Kila neuron hupokea inputs, hutumia weighted sum, kisha hupitisha matokeo kupitia activation function ili kutoa output. Layers zinaweza kugawanywa kama ifuatavyo:
- **Input Layer**: Layer ya kwanza inayopokea input data.
- **Hidden Layers**: Layers za kati zinazofanya transformations kwenye input data. Idadi ya hidden layers na neurons katika kila layer inaweza kutofautiana, na kusababisha architectures tofauti.
- **Output Layer**: Layer ya mwisho inayotoa output ya network, kama vile class probabilities katika classification tasks.


### Activation Functions

Layer ya neurons inapochakata input data, kila neuron hutumia weight na bias kwenye input (`z = w * x + b`), ambapo `w` ni weight, `x` ni input, na `b` ni bias. Output ya neuron kisha hupitishwa kupitia **activation function ili kuingiza non-linearity** kwenye model. Activation function hii huonyesha kimsingi ikiwa neuron inayofuata "inapaswa ku-activate na kwa kiwango gani". Hii huwezesha network kujifunza mifumo na mahusiano changamano katika data, na kuiwezesha kukadiria function yoyote continuous.

Kwa hiyo, activation functions huingiza non-linearity kwenye neural network, na kuiwezesha kujifunza mahusiano changamano katika data. Activation functions za kawaida ni pamoja na:
- **Sigmoid**: Huweka input values katika range kati ya 0 na 1, na mara nyingi hutumika katika binary classification.
- **ReLU (Rectified Linear Unit)**: Hutoa input moja kwa moja ikiwa ni positive; vinginevyo, hutoa zero. Hutumika sana kwa sababu ya urahisi na ufanisi wake katika training ya deep networks.
- **Tanh**: Huweka input values katika range kati ya -1 na 1, na mara nyingi hutumika katika hidden layers.
- **Softmax**: Hubadilisha raw scores kuwa probabilities, na mara nyingi hutumika katika output layer kwa multi-class classification.

### Backpropagation

Backpropagation ni algorithm inayotumika kufundisha neural networks kwa kurekebisha weights za connections kati ya neurons. Hufanya kazi kwa kukokotoa gradient ya loss function kulingana na kila weight, kisha kusasisha weights katika mwelekeo kinyume na gradient ili kupunguza loss. Hatua zinazohusika katika backpropagation ni:

1. **Forward Pass**: Kokotoa output ya network kwa kupitisha input kupitia layers na kutumia activation functions.
2. **Loss Calculation**: Kokotoa loss (error) kati ya predicted output na true target kwa kutumia loss function (kwa mfano, mean squared error kwa regression, cross-entropy kwa classification).
3. **Backward Pass**: Kokotoa gradients za loss kulingana na kila weight kwa kutumia chain rule ya calculus.
4. **Weight Update**: Sasisha weights kwa kutumia optimization algorithm (kwa mfano, stochastic gradient descent, Adam) ili kupunguza loss.

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Convolutional Neural Networks (CNNs) ni aina maalum ya neural network iliyoundwa kuchakata grid-like data, kama vile images. Zinafaa hasa katika computer vision tasks kutokana na uwezo wake wa kujifunza kiotomatiki spatial hierarchies za features.

Vipengele vikuu vya CNNs ni pamoja na:
- **Convolutional Layers**: Hutumia convolution operations kwenye input data kwa kutumia learnable filters (kernels) ili kutoa local features. Kila filter huteleza juu ya input na kukokotoa dot product, na kutoa feature map.
- **Pooling Layers**: Hupunguza ukubwa wa feature maps ili kupunguza spatial dimensions zake huku zikihifadhi features muhimu. Pooling operations za kawaida ni pamoja na max pooling na average pooling.
- **Fully Connected Layers**: Huunganisha kila neuron katika layer moja na kila neuron katika layer inayofuata, sawa na traditional neural networks. Layers hizi kwa kawaida hutumika mwishoni mwa network kwa classification tasks.

Ndani ya **`Convolutional Layers`** za CNN, tunaweza pia kutofautisha kati ya:
- **Initial Convolutional Layer**: Convolutional layer ya kwanza inayochakata raw input data (kwa mfano, image) na ni muhimu kwa kutambua features za msingi kama edges na textures.
- **Intermediate Convolutional Layers**: Convolutional layers zinazofuata zinazojenga juu ya features zilizojifunzwa na initial layer, na kuiwezesha network kujifunza mifumo na representations changamano zaidi.
- **Final Convolutional Layer**: Convolutional layers za mwisho kabla ya fully connected layers, zinazokusanya high-level features na kuandaa data kwa classification.

> [!TIP]
> CNNs zinafaa hasa kwa image classification, object detection, na image segmentation tasks kutokana na uwezo wake wa kujifunza spatial hierarchies za features katika grid-like data na kupunguza idadi ya parameters kupitia weight sharing.
> Zaidi ya hayo, hufanya kazi vizuri zaidi na data inayounga mkono feature locality principle, ambapo data zinazopakana (pixels) zina uwezekano mkubwa wa kuhusiana kuliko pixels zilizo mbali, jambo ambalo huenda lisiwe hivyo kwa aina nyingine za data kama text.
> Pia, kumbuka kuwa CNNs zitaweza kutambua hata features changamano, lakini hazitaweza kutumia spatial context yoyote; hii inamaanisha kuwa feature ileile inayopatikana katika sehemu tofauti za image itakuwa ileile.

### Example defining a CNN

*Hapa utapata maelezo ya jinsi ya kufafanua Convolutional Neural Network (CNN) katika PyTorch ambayo huanza na batch ya RGB images kama dataset yenye ukubwa wa 48x48 na kutumia convolutional layers na maxpool kutoa features, ikifuatiwa na fully connected layers kwa classification.*

Hivi ndivyo unavyoweza kufafanua convolutional layer 1 katika PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Idadi ya input channels. Kwa RGB images, hii ni 3 (moja kwa kila color channel). Ikiwa unafanya kazi na grayscale images, hii itakuwa 1.

- `out_channels`: Idadi ya output channels (filters) ambazo convolutional layer itajifunza. Hii ni hyperparameter ambayo unaweza kurekebisha kulingana na model architecture yako.

- `kernel_size`: Ukubwa wa convolutional filter. Chaguo la kawaida ni 3x3, linalomaanisha kuwa filter itafunika eneo la 3x3 la input image. Hii ni kama stamp ya rangi ya 3×3×3 inayotumika kutengeneza out_channels kutoka kwa in_channels:
1. Weka stamp hiyo ya 3×3×3 kwenye kona ya juu kushoto ya image cube.
2. Zidisha kila weight kwa pixel iliyo chini yake, zijumlishe zote, kisha ongeza bias → utapata namba moja.
3. Andika namba hiyo kwenye map tupu katika nafasi ya (0, 0).
4. Telezesha stamp pixel moja kwenda kulia (stride = 1) na urudie hadi ujaze grid nzima ya 48×48.

- `padding`: Idadi ya pixels zinazoongezwa katika kila upande wa input. Padding husaidia kuhifadhi spatial dimensions za input, na kutoa udhibiti zaidi wa ukubwa wa output. Kwa mfano, kwa kernel ya 3x3 na input ya pixels 48x48, padding ya 1 itaweka ukubwa wa output kuwa uleule (48x48) baada ya convolution operation. Hii ni kwa sababu padding huongeza border ya pixel 1 kuzunguka input image, na kuiruhusu kernel kuteleza juu ya edges bila kupunguza spatial dimensions.

Kisha, idadi ya trainable parameters katika layer hii ni:
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 trainable parameters.

Kumbuka kuwa Bias (+1) huongezwa kwa kila kernel inayotumika kwa sababu kazi ya kila convolutional layer ni kujifunza linear transformation ya input, inayowakilishwa na equation:
```plaintext
Y = f(W * X + b)
```
ambapo `W` ni weight matrix (learned filters, 3x3x3 = 27 params), `b` ni bias vector ambayo ni +1 kwa kila output channel.

Kumbuka kwamba output ya `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` itakuwa tensor yenye shape `(batch_size, 32, 48, 48)`, kwa sababu 32 ni idadi mpya ya generated channels zenye ukubwa wa pixels 48x48.

Kisha, tunaweza kuunganisha convolutional layer hii na convolutional layer nyingine kama hii: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Ambayo itaongeza: (32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 trainable parameters na output yenye shape `(batch_size, 64, 48, 48)`.

Kama unavyoona, **number of parameters huongezeka haraka kwa kila convolutional layer inayoongezwa**, hasa kadiri idadi ya output channels inavyoongezeka.

Njia moja ya kudhibiti kiasi cha data kinachotumika ni kutumia **max pooling** baada ya kila convolutional layer. Max pooling hupunguza spatial dimensions za feature maps, jambo linalosaidia kupunguza idadi ya parameters na computational complexity huku ikihifadhi features muhimu.

Inaweza kutangazwa kama: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Hii inaashiria kutumia grid ya pixels 2x2 na kuchukua thamani ya juu zaidi kutoka kwa kila grid ili kupunguza ukubwa wa feature map kwa nusu. Zaidi ya hayo, `stride=2` inamaanisha kwamba pooling operation itasogea pixels 2 kwa wakati mmoja; katika hali hii, inazuia overlap yoyote kati ya pooling regions.

Kwa pooling layer hii, output shape baada ya convolutional layer ya kwanza itakuwa `(batch_size, 64, 24, 24)` baada ya kutumia `self.pool1` kwenye output ya `self.conv2`, hivyo kupunguza ukubwa hadi 1/4 ya layer iliyotangulia.

> [!TIP]
> Ni muhimu kufanya pooling baada ya convolutional layers ili kupunguza spatial dimensions za feature maps, jambo linalosaidia kudhibiti idadi ya parameters na computational complexity huku ikifanya initial parameter ijifunze features muhimu.
>Unaweza kuona convolutions kabla ya pooling layer kama njia ya kutoa features kutoka kwenye input data (kama mistari na edges); taarifa hii bado itakuwepo kwenye pooled output, lakini convolutional layer inayofuata haitaweza kuona original input data, itaona tu pooled output, ambayo ni toleo lililopunguzwa la layer iliyotangulia lenye taarifa hiyo.
>Kwa mpangilio wa kawaida: `Conv → ReLU → Pool`, kila 2×2 pooling window sasa hushughulika na feature activations (“edge present / not”), badala ya raw pixel intensities. Kuhifadhi activation yenye nguvu zaidi kwa hakika huhifadhi ushahidi muhimu zaidi.

Kisha, baada ya kuongeza convolutional na pooling layers nyingi kadiri inavyohitajika, tunaweza ku-flatten output ili kuiingiza kwenye fully connected layers. Hii hufanywa kwa kubadilisha umbo la tensor kuwa 1D vector kwa kila sample kwenye batch:
```python
x = x.view(-1, 64*24*24)
```
Na kwa kutumia vector hii ya 1D yenye vigezo vyote vya mafunzo vilivyotengenezwa na layers za convolutional na pooling zilizotangulia, tunaweza kufafanua layer iliyounganishwa kikamilifu kama:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Ambayo itachukua matokeo yaliyoflatteniwa ya layer iliyotangulia na kuyapanga kwenye hidden units 512.

Kumbuka jinsi layer hii ilivyoongeza `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` trainable parameters, ambalo ni ongezeko kubwa ikilinganishwa na convolutional layers. Hii ni kwa sababu fully connected layers huunganisha kila neuron katika layer moja na kila neuron katika layer inayofuata, na hivyo kusababisha idadi kubwa ya parameters.

Hatimaye, tunaweza kuongeza output layer ili kutoa class logits za mwisho:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Hii itaongeza vigezo vinavyoweza kufunzwa `(512 + 1 (bias)) * num_classes`, ambapo `num_classes` ni idadi ya madarasa katika kazi ya classification (kwa mfano, 43 kwa dataset ya GTSRB).

Mbinu nyingine ya kawaida ni kuongeza dropout layer kabla ya fully connected layers ili kuzuia overfitting. Hili linaweza kufanywa kwa:
```python
self.dropout = nn.Dropout(0.5)
```
Safu hii huweka kwa nasibu sehemu ya vitengo vya ingizo kuwa sifuri wakati wa mafunzo, jambo linalosaidia kuzuia overfitting kwa kupunguza utegemezi wa neurons maalum.

### Mfano wa code ya CNN
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
### Mfano wa mafunzo wa CNN Code

Code ifuatayo itaunda training data na kufundisha model ya `MY_NET` iliyofafanuliwa hapo juu. Baadhi ya thamani za kuvutia za kuzingatia:

- `EPOCHS` ni idadi ya mara ambazo model itaona dataset nzima wakati wa mafunzo. Ikiwa EPOCH ni ndogo sana, model inaweza isijifunze vya kutosha; ikiwa ni kubwa sana, inaweza kufanya overfit.
- `LEARNING_RATE` ni ukubwa wa hatua wa optimizer. Learning rate ndogo inaweza kusababisha convergence ya polepole, ilhali kubwa inaweza kuvuka solution bora na kuzuia convergence.
- `WEIGHT_DECAY` ni istilahi ya regularization inayosaidia kuzuia overfitting kwa kuadhibu weights kubwa.

Kuhusu training loop, haya ni baadhi ya maelezo muhimu ya kujua:
- `criterion = nn.CrossEntropyLoss()` ni loss function inayotumika kwa kazi za multi-class classification. Inachanganya softmax activation na cross-entropy loss katika function moja, hivyo kuifanya ifae kwa kufundisha models zinazotoa class logits.
- Ikiwa model ilitarajiwa kutoa aina nyingine za outputs, kama binary classification au regression, tungetumia loss functions tofauti kama `nn.BCEWithLogitsLoss()` kwa binary classification au `nn.MSELoss()` kwa regression.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` huanzisha Adam optimizer, ambayo ni chaguo maarufu kwa kufundisha deep learning models. Hubadilisha learning rate kwa kila parameter kulingana na moments ya kwanza na ya pili ya gradients.
- Optimizers nyingine kama `optim.SGD` (Stochastic Gradient Descent) au `optim.RMSprop` zinaweza pia kutumika, kulingana na mahitaji mahususi ya training task.
- Method ya `model.train()` huweka model katika training mode, ikiwezesha layers kama dropout na batch normalization kufanya kazi kwa njia tofauti wakati wa mafunzo ikilinganishwa na evaluation.
- `optimizer.zero_grad()` husafisha gradients za tensors zote zinazoboreshwa kabla ya backward pass, jambo linalohitajika kwa sababu gradients hukusanyika kwa default katika PyTorch. Zisiposafishwa, gradients kutoka iterations zilizopita zingeongezwa kwenye gradients za sasa, na kusababisha updates zisizo sahihi.
- `loss.backward()` hukokotoa gradients za loss kuhusiana na model parameters, ambazo hutumiwa na optimizer kusasisha weights.
- `optimizer.step()` husasisha model parameters kulingana na gradients zilizokokotolewa na learning rate.
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
## Recurrent Neural Networks (RNNs) <sup>[[3]](#references)</sup>

Recurrent Neural Networks (RNNs) ni aina ya neural networks zilizoundwa kwa ajili ya kuchakata data za mfuatano, kama vile time series au lugha ya asili. Tofauti na feedforward neural networks za kawaida, RNNs zina connections zinazojirudia zenyewe, hivyo kuziruhusu kudumisha hidden state inayohifadhi taarifa kuhusu inputs zilizotangulia katika mfuatano.

Vipengele vikuu vya RNNs ni pamoja na:
- **Recurrent Layers**: Layers hizi huchakata input sequences hatua moja ya muda kwa wakati, zikisasisha hidden state yao kulingana na input ya sasa na hidden state ya awali. Hii huwezesha RNNs kujifunza temporal dependencies katika data.
- **Hidden State**: Hidden state ni vector inayofupisha taarifa kutoka hatua za muda zilizotangulia. Husasishwa katika kila hatua ya muda na hutumika kufanya predictions kwa input ya sasa.
- **Output Layer**: Output layer hutoa predictions za mwisho kulingana na hidden state. Mara nyingi, RNNs hutumika kwa kazi kama language modeling, ambapo output ni probability distribution ya neno linalofuata katika mfuatano.

Kwa mfano, katika language model, RNN huchakata mfuatano wa maneno, kwa mfano, "The cat sat on the" na hutabiri neno linalofuata kulingana na context iliyotolewa na maneno yaliyotangulia, katika hali hii, "mat".

### Long Short-Term Memory (LSTM) and Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

RNNs zinafaa hasa kwa kazi zinazohusisha sequential data, kama vile language modeling, machine translation, na speech recognition. Hata hivyo, zinaweza kupata changamoto katika **long-range dependencies kutokana na masuala kama vanishing gradients**.

Ili kushughulikia hili, architectures maalum kama Long Short-Term Memory (LSTM) na Gated Recurrent Unit (GRU) zilitengenezwa. Architectures hizi huanzisha gating mechanisms zinazodhibiti mtiririko wa taarifa, na kuziruhusu kushughulikia long-range dependencies kwa ufanisi zaidi.

- **LSTM**: LSTM networks hutumia gates tatu (input gate, forget gate, na output gate) kudhibiti mtiririko wa taarifa kuingia na kutoka kwenye cell state, na kuziwezesha kukumbuka au kusahau taarifa katika sequences ndefu. Input gate hudhibiti kiasi cha taarifa mpya kinachoongezwa kulingana na input na hidden state ya awali, huku forget gate ikidhibiti kiasi cha taarifa kinachotupwa. Kwa kuchanganya input gate na forget gate tunapata state mpya. Hatimaye, kwa kuchanganya cell state mpya na input pamoja na hidden state ya awali, tunapata pia hidden state mpya.
- **GRU**: GRU networks hurahisisha LSTM architecture kwa kuchanganya input gate na forget gate kuwa update gate moja, hivyo kuzifanya ziwe na ufanisi zaidi wa computational huku zikiendelea kushughulikia long-range dependencies.

## LLMs (Large Language Models)

Large Language Models (LLMs) ni aina ya deep learning models zilizoundwa mahususi kwa ajili ya kazi za natural language processing. Hufunzwa kwa kiasi kikubwa sana cha text data na zinaweza kuzalisha text inayofanana na ya binadamu, kujibu maswali, kutafsiri lugha, na kutekeleza kazi nyingine mbalimbali zinazohusiana na lugha.
LLMs kwa kawaida hutegemea transformer architectures, ambazo hutumia self-attention mechanisms kunasa uhusiano kati ya maneno katika mfuatano, na kuziwezesha kuelewa context na kuzalisha text yenye mshikamano.

### Transformer Architecture <sup>[[4]](#references)</sup>
Transformer architecture ndiyo msingi wa LLMs nyingi. Inajumuisha muundo wa encoder-decoder, ambapo encoder huchakata input sequence na decoder huzalisha output sequence. Vipengele muhimu vya transformer architecture ni pamoja na:
- **Self-Attention Mechanism**: Mechanism hii huwezesha model kupima umuhimu wa maneno mbalimbali katika mfuatano wakati wa kuzalisha representations. Hukokotoa attention scores kulingana na uhusiano kati ya maneno, na kuiwezesha model kulenga context inayohusika.
- **Multi-Head Attention**: Kipengele hiki huwezesha model kunasa uhusiano mbalimbali kati ya maneno kwa kutumia attention heads nyingi, ambapo kila moja hulenga vipengele tofauti vya input.
- **Positional Encoding**: Kwa kuwa transformers hazina dhana iliyojengwa ndani ya mpangilio wa maneno, positional encoding huongezwa kwenye input embeddings ili kutoa taarifa kuhusu nafasi ya maneno katika mfuatano.

## Diffusion Models <sup>[[5]](#references)</sup>
Diffusion models ni aina ya generative models zinazojifunza kuzalisha data kwa kuiga diffusion process. Zinafaa hasa kwa kazi kama image generation na zimepata umaarufu katika miaka ya hivi karibuni.
Diffusion models hufanya kazi kwa kubadilisha hatua kwa hatua simple noise distribution kuwa complex data distribution kupitia mfululizo wa diffusion steps. Vipengele muhimu vya diffusion models ni pamoja na:
- **Forward Diffusion Process**: Process hii huongeza noise kwenye data hatua kwa hatua, na kuibadilisha kuwa simple noise distribution. Forward diffusion process kwa kawaida hufafanuliwa na mfululizo wa noise levels, ambapo kila level inawakilisha kiasi maalum cha noise kilichoongezwa kwenye data.
- **Reverse Diffusion Process**: Process hii hujifunza kubadilisha forward diffusion process, ikiondoa noise kwenye data hatua kwa hatua ili kuzalisha samples kutoka kwenye target distribution. Reverse diffusion process hufunzwa kwa kutumia loss function inayohimiza model kuunda upya data ya awali kutoka kwenye noisy samples.

Zaidi ya hayo, ili kuzalisha image kutoka kwenye text prompt, diffusion models kwa kawaida hufuata hatua hizi:
1. **Text Encoding**: Text prompt husimbwa kuwa latent representation kwa kutumia text encoder (kwa mfano, model inayotegemea transformer). Representation hii hunasa maana ya kisemantiki ya text.
2. **Noise Sampling**: Random noise vector huchukuliwa kutoka kwenye Gaussian distribution.
3. **Diffusion Steps**: Model hutumia mfululizo wa diffusion steps, ikibadilisha noise vector hatua kwa hatua kuwa image inayolingana na text prompt. Kila hatua inahusisha kutumia learned transformations ili kuondoa noise kwenye image.

## References

- [1] [PyTorch - Mafunzo ya Neural Networks](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Denoising Diffusion Probabilistic Models](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
