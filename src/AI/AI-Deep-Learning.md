# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning <sup>[[1]](#references)</sup>

Deep learning, verilerdeki karmaşık örüntüleri modellemek için birden fazla katmana sahip neural network'leri (deep neural network'ler) kullanan machine learning alt kümesidir. Computer vision, natural language processing ve speech recognition dahil olmak üzere çeşitli alanlarda dikkate değer başarı elde etmiştir.

### Neural Network'ler

Neural network'ler, deep learning'in yapı taşlarıdır. Katmanlar halinde düzenlenmiş birbirine bağlı düğümlerden (nöronlardan) oluşurlar. Her nöron girdileri alır, ağırlıklı bir toplam uygular ve bir çıktı üretmek için sonucu bir activation function'dan geçirir. Katmanlar şu şekilde kategorilere ayrılabilir:
- **Input Layer**: Girdi verilerini alan ilk katmandır.
- **Hidden Layers**: Girdi verileri üzerinde dönüşümler gerçekleştiren ara katmanlardır. Hidden layer'ların sayısı ve her katmandaki nöron sayısı değişebilir; bu da farklı mimarilerin ortaya çıkmasını sağlar.
- **Output Layer**: Classification görevlerindeki sınıf olasılıkları gibi network'ün çıktısını üreten son katmandır.


### Activation Function'lar

Bir nöron katmanı girdi verilerini işlediğinde, her nöron girdiye bir ağırlık ve bias uygular (`z = w * x + b`); burada `w` ağırlık, `x` girdi ve `b` bias'tır. Nöronun çıktısı daha sonra modele **doğrusal olmayanlık kazandırmak için bir activation function'dan geçirilir**. Bu activation function temel olarak bir sonraki nöronun "etkinleştirilip etkinleştirilmeyeceğini ve ne ölçüde etkinleştirileceğini" belirtir. Bu, network'ün verilerdeki karmaşık örüntüleri ve ilişkileri öğrenmesini ve böylece herhangi bir sürekli fonksiyona yaklaşabilmesini sağlar.

Bu nedenle activation function'lar neural network'e doğrusal olmayanlık kazandırarak verilerdeki karmaşık ilişkileri öğrenmesini sağlar. Yaygın activation function'lar şunlardır:
- **Sigmoid**: Girdi değerlerini 0 ile 1 arasındaki bir aralığa eşler; genellikle binary classification'da kullanılır.
- **ReLU (Rectified Linear Unit)**: Girdi pozitifse doğrudan girdiyi, aksi durumda sıfırı verir. Basitliği ve deep network'lerin training sürecindeki etkinliği nedeniyle yaygın olarak kullanılır.
- **Tanh**: Girdi değerlerini -1 ile 1 arasındaki bir aralığa eşler; genellikle hidden layer'larda kullanılır.
- **Softmax**: Ham skorları olasılıklara dönüştürür; genellikle multi-class classification için output layer'da kullanılır.

### Backpropagation

Backpropagation, nöronlar arasındaki bağlantıların ağırlıklarını ayarlayarak neural network'leri train etmek için kullanılan algoritmadır. Her ağırlığa göre loss function'ın gradient'ini hesaplayarak ve loss'u en aza indirmek için ağırlıkları gradient'in tersi yönde güncelleyerek çalışır. Backpropagation sürecindeki adımlar şunlardır:

1. **Forward Pass**: Girdiyi katmanlardan geçirip activation function'ları uygulayarak network'ün çıktısını hesaplayın.
2. **Loss Calculation**: Bir loss function kullanarak tahmin edilen çıktı ile gerçek hedef arasındaki loss'u (hatayı) hesaplayın (ör. regression için mean squared error, classification için cross-entropy).
3. **Backward Pass**: Calculus'un chain rule'unu kullanarak loss'un her ağırlığa göre gradient'lerini hesaplayın.
4. **Weight Update**: Loss'u en aza indirmek için bir optimization algorithm (ör. stochastic gradient descent, Adam) kullanarak ağırlıkları güncelleyin.

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Convolutional Neural Networks (CNNs), görüntüler gibi grid benzeri verileri işlemek için tasarlanmış özel bir neural network türüdür. Özelliklerin uzamsal hiyerarşilerini otomatik olarak öğrenebilme yetenekleri sayesinde computer vision görevlerinde özellikle etkilidirler.

CNN'lerin ana bileşenleri şunlardır:
- **Convolutional Layers**: Yerel özellikleri çıkarmak için learnable filter'lar (kernel'ler) kullanarak girdi verilerine convolution işlemleri uygular. Her filter girdi üzerinde kayar ve bir dot product hesaplayarak bir feature map üretir.
- **Pooling Layers**: Önemli özellikleri korurken uzamsal boyutlarını azaltmak için feature map'leri downsample eder. Yaygın pooling işlemleri arasında max pooling ve average pooling bulunur.
- **Fully Connected Layers**: Bir katmandaki her nöronu sonraki katmandaki her nörona bağlar; bu yönüyle geleneksel neural network'lere benzer. Bu katmanlar genellikle network'ün sonunda classification görevleri için kullanılır.

Bir CNN içindeki **`Convolutional Layers`** arasında ayrıca şunları ayırt edebiliriz:
- **Initial Convolutional Layer**: Ham girdi verilerini (ör. bir görüntü) işleyen ilk convolutional layer'dır ve kenarlar ile dokular gibi temel özellikleri tanımlamak için kullanışlıdır.
- **Intermediate Convolutional Layers**: Initial layer tarafından öğrenilen özellikler üzerine inşa edilen sonraki convolutional layer'lardır; network'ün daha karmaşık örüntüleri ve temsilleri öğrenmesini sağlar.
- **Final Convolutional Layer**: Fully connected layer'lardan önceki son convolutional layer'lardır; üst düzey özellikleri yakalar ve verileri classification için hazırlar.

> [!TIP]
> CNN'ler, grid benzeri verilerde özelliklerin uzamsal hiyerarşilerini öğrenebilme ve weight sharing yoluyla parametre sayısını azaltabilme yetenekleri sayesinde image classification, object detection ve image segmentation görevlerinde özellikle etkilidir.
> Ayrıca, feature locality principle'ı destekleyen verilerle daha iyi çalışırlar; bu prensibe göre komşu verilerin (pikselerin) uzak piksellere kıyasla birbiriyle ilişkili olma olasılığı daha yüksektir. Bu durum text gibi diğer veri türleri için geçerli olmayabilir.
> Dahası, CNN'lerin karmaşık özellikleri bile tanımlayabildiğini ancak herhangi bir uzamsal context uygulayamadığını unutmayın; yani görüntünün farklı bölümlerinde bulunan aynı özellik aynı olacaktır.

### CNN tanımlama örneği

*Burada, dataset olarak 48x48 boyutunda RGB görüntü batch'i ile başlayan ve özellikleri çıkarmak için convolutional layer'lar ile maxpool kullanan, ardından classification için fully connected layer'lar kullanan bir Convolutional Neural Network'ün (CNN) PyTorch'ta nasıl tanımlanacağı açıklanmaktadır.*

PyTorch'ta 1 convolutional layer'ı şu şekilde tanımlayabilirsiniz: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Girdi kanallarının sayısıdır. RGB görüntülerde bu değer 3'tür (her renk kanalı için bir tane). Grayscale görüntülerle çalışıyorsanız bu değer 1 olur.

- `out_channels`: Convolutional layer'ın öğreneceği çıktı kanallarının (filter'ların) sayısıdır. Bu, model mimarinize göre ayarlayabileceğiniz bir hyperparameter'dır.

- `kernel_size`: Convolutional filter'ın boyutudur. Yaygın bir seçim 3x3'tür; bu, filter'ın girdi görüntüsünün 3x3'lük bir alanını kaplayacağı anlamına gelir. Bu, `in_channels`'tan `out_channels`'ı üretmek için kullanılan 3×3×3 renk damgası gibidir:
1. Bu 3×3×3 damgayı görüntü küpünün sol üst köşesine yerleştirin.
2. Her ağırlığı altındaki piksel ile çarpın, hepsini toplayın ve bias'ı ekleyin → bir sayı elde edersiniz.
3. Bu sayıyı boş bir haritada (0, 0) konumuna yazın.
4. Damgayı bir piksel sağa kaydırın (stride = 1) ve 48×48'lik grid'in tamamını doldurana kadar tekrarlayın.

- `padding`: Girdinin her tarafına eklenen piksel sayısıdır. Padding, girdinin uzamsal boyutlarının korunmasına yardımcı olarak çıktı boyutu üzerinde daha fazla kontrol sağlar. Örneğin, 3x3 kernel ve 48x48 piksellik bir girdide padding değerinin 1 olması, convolution işleminden sonra çıktı boyutunu aynı (48x48) tutar. Bunun nedeni, padding'in girdi görüntüsünün çevresine 1 piksel genişliğinde bir kenarlık ekleyerek kernel'in uzamsal boyutları azaltmadan kenarlar üzerinde kayabilmesini sağlamasıdır.

Daha sonra, bu katmandaki trainable parameter'ların sayısı:
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 trainable parameter.

Her kullanılan kernel için bir Bias (+1) eklendiğini unutmayın; çünkü her convolutional layer'ın işlevi, şu denklemle gösterilen girdi üzerinde doğrusal bir dönüşüm öğrenmektir:
```plaintext
Y = f(W * X + b)
```
burada `W`, ağırlık matrisi (öğrenilen filtreler, 3x3x3 = 27 parametre), `b` ise her output channel için +1 olan bias vektörüdür.

`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` çıktısının `(batch_size, 32, 48, 48)` şeklinde bir tensor olacağını unutmayın; çünkü 32, 48x48 piksel boyutunda oluşturulan yeni channel sayısıdır.

Daha sonra bu convolutional layer'ı başka bir convolutional layer'a şu şekilde bağlayabiliriz: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Bu işlem şunları ekler: (32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 trainable parameter ve `(batch_size, 64, 48, 48)` şeklinde bir output.

Gördüğünüz gibi, özellikle output channel sayısı arttıkça, **her ek convolutional layer ile parameter sayısı hızla artar**.

Kullanılan data miktarını kontrol etmek için bir seçenek, her convolutional layer'dan sonra **max pooling** kullanmaktır. Max pooling, feature map'lerin spatial dimension'larını azaltır; bu da önemli feature'ları korurken parameter sayısını ve computational complexity'yi düşürmeye yardımcı olur.

Şu şekilde tanımlanabilir: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Bu, temelde 2x2 piksellik bir grid kullanıp feature map'in boyutunu yarıya indirmek için her grid'deki maksimum değeri almayı belirtir. Ayrıca, `stride=2`, pooling işleminin her seferinde 2 piksel ilerleyeceği anlamına gelir; bu durumda pooling bölgeleri arasında overlap oluşmasını önler.

Bu pooling layer ile ilk convolutional layer'dan sonraki output shape, `self.pool1` öğesinin `self.conv2` output'una uygulanmasından sonra `(batch_size, 64, 24, 24)` olur ve boyut önceki layer'ın 1/4'üne düşer.

> [!TIP]
> Feature map'lerin spatial dimension'larını azaltmak için convolutional layer'ların ardından pooling uygulamak önemlidir. Bu, parameter sayısını ve computational complexity'yi kontrol etmeye yardımcı olurken başlangıçtaki parameter'ların önemli feature'ları öğrenmesini sağlar.
>Pooling layer'dan önceki convolution işlemlerini input data'dan (örneğin çizgiler ve kenarlar) feature çıkarma yöntemi olarak görebilirsiniz. Bu bilgiler pooled output içinde hâlâ bulunur; ancak sonraki convolutional layer artık original input data'yı göremez, yalnızca bu bilgileri içeren ve önceki layer'ın azaltılmış bir sürümü olan pooled output'u görür.
>Genellikle kullanılan sırada: `Conv → ReLU → Pool`, her 2×2 pooling window artık ham piksel yoğunluklarıyla değil, feature activation'larıyla (“kenar var / yok”) karşılaşır. En güçlü activation'ı korumak, gerçekten de en önemli kanıtı korur.

Daha sonra, ihtiyacımız olan sayıda convolutional ve pooling layer ekledikten sonra output'u fully connected layer'lara aktarmak için flatten edebiliriz. Bu işlem, tensor'ü batch içindeki her sample için 1D bir vector olacak şekilde yeniden şekillendirerek yapılır:
```python
x = x.view(-1, 64*24*24)
```
Ve önceki convolutional ve pooling katmanları tarafından oluşturulan tüm training parametrelerini içeren bu 1D vektör ile şu şekilde bir fully connected layer tanımlayabiliriz:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Önceki katmanın düzleştirilmiş çıktısını alıp 512 gizli birime eşleyecektir.

Bu katmanın `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` eğitilebilir parametre eklediğine dikkat edin; bu, convolutional katmanlara kıyasla önemli bir artıştır. Bunun nedeni, fully connected katmanların bir katmandaki her nöronu sonraki katmandaki her nörona bağlaması ve bunun da çok sayıda parametreye yol açmasıdır.

Son olarak, nihai sınıf logits'lerini üretmek için bir output layer ekleyebiliriz:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Bu, `num_classes` sınıflandırma görevindeki sınıf sayısı olduğunda (örneğin, GTSRB veri kümesi için 43), `(512 + 1 (bias)) * num_classes` eğitilebilir parametre ekler.

Bir diğer yaygın uygulama, overfitting'i önlemek için fully connected katmanlardan önce bir dropout katmanı eklemektir. Bu işlem şu şekilde yapılabilir:
```python
self.dropout = nn.Dropout(0.5)
```
Bu katman, eğitim sırasında giriş birimlerinin bir kısmını rastgele sıfıra ayarlar; bu, belirli nöronlara olan bağımlılığı azaltarak overfitting'i önlemeye yardımcı olur.

### CNN Code örneği
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
### CNN Code eğitim örneği

Aşağıdaki kod, bazı training data oluşturacak ve yukarıda tanımlanan `MY_NET` modelini train edecektir. Dikkat edilmesi gereken bazı ilginç değerler:

- `EPOCHS`, modelin training sırasında tüm dataset'i kaç kez göreceğini belirtir. EPOCH çok küçükse model yeterince öğrenemeyebilir; çok büyükse overfit olabilir.
- `LEARNING_RATE`, optimizer için step size'dır. Küçük bir learning rate yavaş convergence'a yol açabilirken, büyük bir learning rate optimal çözümü aşabilir ve convergence'ı engelleyebilir.
- `WEIGHT_DECAY`, büyük weight'leri cezalandırarak overfitting'i önlemeye yardımcı olan bir regularization terimidir.

Training loop hakkında bilinmesi gereken bazı ilginç bilgiler:
- `criterion = nn.CrossEntropyLoss()`, multi-class classification görevlerinde kullanılan loss function'dır. Softmax activation ile cross-entropy loss'u tek bir function'da birleştirerek class logits üreten modelleri train etmek için uygun hale getirir.
- Modelin binary classification veya regression gibi farklı output türleri üretmesi bekleniyorsa, binary classification için `nn.BCEWithLogitsLoss()` veya regression için `nn.MSELoss()` gibi farklı loss function'lar kullanırdık.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)`, deep learning modellerini train etmek için popüler bir tercih olan Adam optimizer'ını başlatır. Gradient'lerin first ve second moment'larına göre her parameter için learning rate'i uyarlar.
- Training task'ın özel gereksinimlerine bağlı olarak `optim.SGD` (Stochastic Gradient Descent) veya `optim.RMSprop` gibi diğer optimizer'lar da kullanılabilir.
- `model.train()` method'u modeli training mode'a geçirir ve dropout ile batch normalization gibi layer'ların training sırasında evaluation'a kıyasla farklı davranmasını sağlar.
- `optimizer.zero_grad()`, backward pass öncesinde optimize edilen tüm tensor'ların gradient'lerini temizler. Bu gereklidir, çünkü PyTorch'ta gradient'ler varsayılan olarak birikir. Temizlenmezse önceki iteration'lardaki gradient'ler mevcut gradient'lere eklenir ve hatalı update'lere yol açar.
- `loss.backward()`, loss'un model parameter'larına göre gradient'lerini hesaplar. Bu gradient'ler daha sonra optimizer tarafından weight'leri güncellemek için kullanılır.
- `optimizer.step()`, hesaplanan gradient'lere ve learning rate'e göre model parameter'larını günceller.
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

Recurrent Neural Networks (RNNs), zaman serileri veya doğal dil gibi sıralı verileri işlemek için tasarlanmış bir neural network sınıfıdır. Geleneksel feedforward neural network'lerin aksine RNN'ler, kendilerine geri dönen bağlantılara sahiptir. Bu, dizideki önceki girdiler hakkındaki bilgileri yakalayan bir hidden state'i korumalarını sağlar.

RNN'lerin ana bileşenleri şunlardır:
- **Recurrent Layers**: Bu katmanlar input sequence'lerini her seferinde bir time step işleyerek hidden state'lerini mevcut input'a ve önceki hidden state'e göre günceller. Bu, RNN'lerin verilerdeki temporal dependencies'leri öğrenmesini sağlar.
- **Hidden State**: Hidden state, önceki time step'lerden gelen bilgileri özetleyen bir vektördür. Her time step'te güncellenir ve mevcut input için tahminler yapmak üzere kullanılır.
- **Output Layer**: Output layer, hidden state'e göre nihai tahminleri üretir. Birçok durumda RNN'ler, output'un bir dizideki sonraki kelime üzerinde bir probability distribution olduğu language modeling gibi görevlerde kullanılır.

Örneğin bir language model'de RNN, "The cat sat on the" gibi bir kelime dizisini işler ve önceki kelimelerin sağladığı bağlama göre sonraki kelimeyi, bu durumda "mat" kelimesini tahmin eder.

### Long Short-Term Memory (LSTM) and Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

RNN'ler language modeling, machine translation ve speech recognition gibi sıralı veriler içeren görevlerde özellikle etkilidir. Ancak **vanishing gradients gibi sorunlar nedeniyle long-range dependencies'leri işleme konusunda zorlanabilirler**.

Bunu ele almak için Long Short-Term Memory (LSTM) ve Gated Recurrent Unit (GRU) gibi özel architecture'lar geliştirildi. Bu architecture'lar, bilgi akışını kontrol eden gating mechanisms'ler sunarak long-range dependencies'leri daha etkili şekilde yakalamalarını sağlar.

- **LSTM**: LSTM network'leri, cell state'e giren ve çıkan bilgi akışını düzenlemek için üç gate (input gate, forget gate ve output gate) kullanır. Böylece bilgiyi uzun diziler boyunca hatırlayabilir veya unutabilirler. Input gate, input'a ve önceki hidden state'e göre ne kadar yeni bilgi ekleneceğini kontrol eder; forget gate ise ne kadar bilginin atılacağını kontrol eder. Input gate ile forget gate'i birleştirdiğimizde yeni state'i elde ederiz. Son olarak yeni cell state'i input ve önceki hidden state ile birleştirerek yeni hidden state'i de elde ederiz.
- **GRU**: GRU network'leri, input gate ve forget gate'i tek bir update gate'te birleştirerek LSTM architecture'ını basitleştirir. Böylece long-range dependencies'leri yakalamaya devam ederken hesaplama açısından daha verimli olurlar.

## LLMs (Large Language Models)

Large Language Models (LLMs), özellikle natural language processing görevleri için tasarlanmış bir deep learning model türüdür. Büyük miktarlarda text data üzerinde eğitilirler ve insan benzeri metinler üretebilir, soruları yanıtlayabilir, dilleri çevirebilir ve dil ile ilgili çeşitli görevleri gerçekleştirebilirler.
LLM'ler genellikle bir dizideki kelimeler arasındaki ilişkileri yakalamak için self-attention mechanisms kullanan transformer architecture'larına dayanır. Bu, bağlamı anlamalarını ve tutarlı metin üretmelerini sağlar.

### Transformer Architecture <sup>[[4]](#references)</sup>
Transformer architecture, birçok LLM'in temelini oluşturur. Encoder'ın input sequence'i işlediği ve decoder'ın output sequence'i ürettiği bir encoder-decoder yapısından oluşur. Transformer architecture'ın temel bileşenleri şunlardır:
- **Self-Attention Mechanism**: Bu mechanism, modelin representation'lar üretirken bir dizideki farklı kelimelerin önemini ağırlıklandırmasını sağlar. Kelimeler arasındaki ilişkilere göre attention scores hesaplayarak modelin ilgili bağlama odaklanmasını sağlar.
- **Multi-Head Attention**: Bu bileşen, her biri input'un farklı yönlerine odaklanan birden fazla attention head kullanarak modelin kelimeler arasındaki birden fazla ilişkiyi yakalamasını sağlar.
- **Positional Encoding**: Transformer'ların yerleşik bir kelime sırası kavramı olmadığından, dizideki kelimelerin konumu hakkında bilgi sağlamak için input embeddings'lere positional encoding eklenir.

## Diffusion Models <sup>[[5]](#references)</sup>
Diffusion models, bir diffusion process'i simüle ederek veri üretmeyi öğrenen generative model sınıfıdır. Image generation gibi görevlerde özellikle etkilidirler ve son yıllarda popülerlik kazanmışlardır.
Diffusion models, bir dizi diffusion step aracılığıyla basit bir noise distribution'ı karmaşık bir data distribution'a kademeli olarak dönüştürerek çalışır. Diffusion models'in temel bileşenleri şunlardır:
- **Forward Diffusion Process**: Bu process, veriye kademeli olarak noise ekleyerek veriyi basit bir noise distribution'a dönüştürür. Forward diffusion process genellikle, her bir seviyenin veriye eklenen belirli bir noise miktarına karşılık geldiği bir dizi noise level ile tanımlanır.
- **Reverse Diffusion Process**: Bu process, forward diffusion process'i tersine çevirmeyi öğrenir ve target distribution'dan örnekler üretmek için verinin noise'unu kademeli olarak giderir. Reverse diffusion process, modelin noisy samples'lardan orijinal veriyi yeniden oluşturmasını teşvik eden bir loss function kullanılarak eğitilir.

Ayrıca diffusion models, bir text prompt'tan image üretmek için genellikle şu adımları izler:
1. **Text Encoding**: Text prompt, bir text encoder (ör. transformer tabanlı bir model) kullanılarak latent representation'a kodlanır. Bu representation, text'in semantic anlamını yakalar.
2. **Noise Sampling**: Gaussian distribution'dan rastgele bir noise vector örneklenir.
3. **Diffusion Steps**: Model, noise vector'ü text prompt'a karşılık gelen bir image'a kademeli olarak dönüştürmek için bir dizi diffusion step uygular. Her step, image'ın noise'unu gidermek için öğrenilmiş transformations'ların uygulanmasını içerir.

## References

- [1] [PyTorch - Neural Networks öğreticisi](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Denoising Diffusion Probabilistic Models](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
