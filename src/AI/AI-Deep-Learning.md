# Derin Öğrenme

{{#include ../banners/hacktricks-training.md}}

## Derin Öğrenme

Derin öğrenme, verilerdeki karmaşık kalıpları modellemek için birden fazla katmana (derin sinir ağları) sahip sinir ağları kullanan makine öğreniminin bir alt kümesidir. Bilgisayarla görme, doğal dil işleme ve konuşma tanıma gibi çeşitli alanlarda dikkate değer başarılar elde etmiştir.

### Sinir Ağları

Sinir ağları, derin öğrenmenin yapı taşlarıdır. Katmanlar halinde düzenlenmiş birbirine bağlı düğümlerden (nöronlar) oluşurlar. Her nöron, girdileri alır, ağırlıklı toplam uygular ve bir çıkış üretmek için sonucu bir aktivasyon fonksiyonundan geçirir. Katmanlar şu şekilde kategorize edilebilir:
- **Girdi Katmanı**: Girdi verilerini alan ilk katman.
- **Gizli Katmanlar**: Girdi verileri üzerinde dönüşümler gerçekleştiren ara katmanlar. Gizli katmanların ve her katmandaki nöron sayısının değişkenlik göstermesi, farklı mimarilere yol açabilir.
- **Çıkış Katmanı**: Ağın çıktısını üreten son katman, örneğin sınıflandırma görevlerinde sınıf olasılıkları.

### Aktivasyon Fonksiyonları

Bir nöron katmanı girdi verilerini işlerken, her nöron girdiye bir ağırlık ve bir bias uygular (`z = w * x + b`), burada `w` ağırlık, `x` girdi ve `b` bias'tır. Nöronun çıktısı daha sonra modele doğrusal olmayanlık eklemek için bir **aktivasyon fonksiyonundan geçirilir**. Bu aktivasyon fonksiyonu, bir sonraki nöronun "aktif hale gelip gelmeyeceğini ve ne kadar aktif olacağını" belirtir. Bu, ağın verilerdeki karmaşık kalıpları ve ilişkileri öğrenmesini sağlar, böylece herhangi bir sürekli fonksiyonu yaklaşık olarak modelleyebilir.

Bu nedenle, aktivasyon fonksiyonları sinir ağına doğrusal olmayanlık katarak verilerdeki karmaşık ilişkileri öğrenmesine olanak tanır. Yaygın aktivasyon fonksiyonları şunlardır:
- **Sigmoid**: Girdi değerlerini 0 ile 1 arasında bir aralığa haritalar, genellikle ikili sınıflandırmada kullanılır.
- **ReLU (Düzeltilmiş Doğrusal Birim)**: Girdi pozitifse doğrudan çıktıyı verir; aksi takdirde sıfır verir. Derin ağların eğitiminde basitliği ve etkinliği nedeniyle yaygın olarak kullanılır.
- **Tanh**: Girdi değerlerini -1 ile 1 arasında bir aralığa haritalar, genellikle gizli katmanlarda kullanılır.
- **Softmax**: Ham puanları olasılıklara dönüştürür, genellikle çok sınıflı sınıflandırma için çıkış katmanında kullanılır.

### Geri Yayılım

Geri yayılım, sinir ağlarını nöronlar arasındaki bağlantıların ağırlıklarını ayarlayarak eğitmek için kullanılan algoritmadır. Kayıp fonksiyonunun her bir ağırlıkla ilgili gradyanını hesaplayarak ve ağırlıkları gradyanın ters yönünde güncelleyerek kaybı minimize eder. Geri yayılımda yer alan adımlar şunlardır:

1. **İleri Geçiş**: Girdiyi katmanlardan geçirerek ve aktivasyon fonksiyonlarını uygulayarak ağın çıktısını hesaplayın.
2. **Kayıp Hesaplama**: Tahmin edilen çıktı ile gerçek hedef arasındaki kaybı (hata) bir kayıp fonksiyonu kullanarak hesaplayın (örneğin, regresyon için ortalama kare hatası, sınıflandırma için çapraz entropi).
3. **Geri Geçiş**: Kayıp ile her bir ağırlık arasındaki gradyanları hesaplayın, kalkülüsün zincir kuralını kullanarak.
4. **Ağırlık Güncelleme**: Kayıbı minimize etmek için bir optimizasyon algoritması (örneğin, stokastik gradyan inişi, Adam) kullanarak ağırlıkları güncelleyin.

## Konvolüsyonel Sinir Ağları (CNN'ler)

Konvolüsyonel Sinir Ağları (CNN'ler), ızgara benzeri verileri, örneğin görüntüleri işlemek için tasarlanmış özel bir sinir ağı türüdür. Özellikle, özelliklerin mekansal hiyerarşilerini otomatik olarak öğrenme yetenekleri nedeniyle bilgisayarla görme görevlerinde oldukça etkilidirler.

CNN'lerin ana bileşenleri şunlardır:
- **Konvolüsyonel Katmanlar**: Girdi verilerine öğrenilebilir filtreler (çekirdekler) kullanarak konvolüsyon işlemleri uygular ve yerel özellikleri çıkarır. Her filtre, girdinin üzerinde kayar ve bir nokta çarpımı hesaplayarak bir özellik haritası üretir.
- **Havuzlama Katmanları**: Önemli özellikleri korurken özellik haritalarının mekansal boyutlarını azaltmak için örnekleme yapar. Yaygın havuzlama işlemleri arasında maksimum havuzlama ve ortalama havuzlama bulunur.
- **Tam Bağlantılı Katmanlar**: Bir katmandaki her nöronu bir sonraki katmandaki her nörona bağlar, geleneksel sinir ağlarına benzer. Bu katmanlar genellikle sınıflandırma görevleri için ağın sonunda kullanılır.

Bir CNN içindeki **`Konvolüsyonel Katmanlar`** arasında ayrıca şunları ayırt edebiliriz:
- **İlk Konvolüsyonel Katman**: Ham girdi verilerini (örneğin, bir görüntü) işleyen ilk konvolüsyonel katman ve kenarlar ve dokular gibi temel özellikleri tanımlamak için faydalıdır.
- **Ara Konvolüsyonel Katmanlar**: İlk katmanın öğrendiği özellikler üzerine inşa eden sonraki konvolüsyonel katmanlar, ağın daha karmaşık kalıpları ve temsilleri öğrenmesine olanak tanır.
- **Son Konvolüsyonel Katman**: Tam bağlantılı katmanlardan önceki son konvolüsyonel katmanlar, yüksek seviyeli özellikleri yakalar ve verileri sınıflandırma için hazırlar.

> [!TIP]
> CNN'ler, ızgara benzeri verilerdeki özelliklerin mekansal hiyerarşilerini öğrenme yetenekleri ve ağırlık paylaşımı yoluyla parametre sayısını azaltma özellikleri nedeniyle görüntü sınıflandırma, nesne tespiti ve görüntü segmentasyonu görevlerinde özellikle etkilidir.
> Ayrıca, komşu verilerin (piksel) uzak pikselere göre daha fazla ilişkili olma olasılığının yüksek olduğu özellik yerelliği ilkesini destekleyen verilerle daha iyi çalıştıklarını unutmayın; bu, metin gibi diğer veri türleri için geçerli olmayabilir.
> Dahası, CNN'lerin karmaşık özellikleri tanımlayabileceğini ancak herhangi bir mekansal bağlam uygulayamayacağını, yani görüntünün farklı bölgelerinde bulunan aynı özelliğin aynı olacağını unutmayın.

### CNN Tanımlama Örneği

*Burada, 48x48 boyutunda bir RGB görüntü kümesi ile başlayan bir Konvolüsyonel Sinir Ağı (CNN) tanımlamanın nasıl yapılacağına dair bir açıklama bulacaksınız ve özellikleri çıkarmak için konvolüsyonel katmanlar ve maksimum havuzlama kullanılır, ardından sınıflandırma için tam bağlantılı katmanlar gelir.*

PyTorch'ta 1 konvolüsyonel katmanı şu şekilde tanımlayabilirsiniz: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Girdi kanallarının sayısı. RGB görüntüleri durumunda bu 3'tür (her renk kanalı için bir tane). Eğer gri tonlamalı görüntülerle çalışıyorsanız, bu 1 olacaktır.

- `out_channels`: Konvolüsyonel katmanın öğreneceği çıktı kanallarının (filtrelerin) sayısıdır. Bu, model mimarinize göre ayarlayabileceğiniz bir hiperparametredir.

- `kernel_size`: Konvolüsyonel filtrenin boyutu. Yaygın bir seçim 3x3'tür, bu da filtrenin girdi görüntüsünün 3x3 alanını kapsayacağı anlamına gelir. Bu, in_channels'tan out_channels'ı üretmek için kullanılan 3×3×3 renk damgası gibidir:
1. O 3×3×3 damgayı görüntü küpünün sol üst köşesine yerleştirin.
2. Her ağırlığı altındaki piksel ile çarpın, hepsini toplayın, bias ekleyin → bir sayı elde edersiniz.
3. O sayıyı boş bir haritada (0, 0) konumuna yazın.
4. Damgayı bir piksel sağa kaydırın (stride = 1) ve 48×48 ızgarayı doldurana kadar tekrarlayın.

- `padding`: Girdiğin her tarafına eklenen piksel sayısı. Padding, çıktının boyutunu daha iyi kontrol edebilmek için girdiğin mekansal boyutlarını korumaya yardımcı olur. Örneğin, 3x3 çekirdek ile 48x48 piksel girdi için, 1'lik bir padding, konvolüsyon işlemi sonrasında çıktı boyutunu aynı (48x48) tutar. Bunun nedeni, padding'in girdi görüntüsünün etrafına 1 piksel genişliğinde bir kenar eklemesi ve çekirdeğin kenarların üzerinden kaymasına olanak tanımasıdır.

Bu katmandaki eğitilebilir parametrelerin sayısı:
- (3x3x3 (çekirdek boyutu) + 1 (bias)) x 32 (out_channels) = 896 eğitilebilir parametre.

Her çekirdek için bir Bias (+1) eklenir çünkü her konvolüsyonel katmanın işlevi, girdinin doğrusal bir dönüşümünü öğrenmektir ve bu, şu denklemi temsil eder:
```plaintext
Y = f(W * X + b)
```
`W` ağırlık matrisidir (öğrenilen filtreler, 3x3x3 = 27 parametre), `b` ise her çıkış kanalı için +1 olan bias vektörüdür.

`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` ifadesinin çıktısının `(batch_size, 32, 48, 48)` şeklinde bir tensör olacağını unutmayın, çünkü 32, 48x48 piksel boyutunda üretilen yeni kanal sayısıdır.

Sonra, bu konvolüsyon katmanını başka bir konvolüsyon katmanına bağlayabiliriz: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Bu, şunları ekleyecektir: (32x3x3 (kernel boyutu) + 1 (bias)) x 64 (out_channels) = 18,496 eğitilebilir parametre ve `(batch_size, 64, 48, 48)` şeklinde bir çıktı.

Gördüğünüz gibi, **parametre sayısı her ek konvolüsyon katmanıyla hızla artar**, özellikle çıkış kanallarının sayısı arttıkça.

Kullanılan veri miktarını kontrol etmenin bir yolu, her konvolüsyon katmanından sonra **max pooling** kullanmaktır. Max pooling, özellik haritalarının mekansal boyutlarını azaltır, bu da parametre sayısını ve hesaplama karmaşıklığını azaltmaya yardımcı olurken önemli özelliklerin korunmasına yardımcı olur.

Şu şekilde tanımlanabilir: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Bu, temel olarak 2x2 piksel ızgarası kullanmayı ve her ızgaradan maksimum değeri alarak özellik haritasının boyutunu yarıya indirmeyi belirtir. Ayrıca, `stride=2` demek, pooling işleminin her seferinde 2 piksel hareket edeceği anlamına gelir; bu durumda, pooling bölgeleri arasında herhangi bir örtüşmeyi önler.

Bu pooling katmanıyla, ilk konvolüsyon katmanından sonra çıktı şekli, `self.conv2` çıktısına `self.pool1` uygulandıktan sonra `(batch_size, 64, 24, 24)` olacaktır ve boyutu önceki katmanın 1/4'üne düşecektir.

> [!TIP]
> Konvolüsyon katmanlarından sonra pooling yapmak, özellik haritalarının mekansal boyutlarını azaltmak için önemlidir; bu, parametre sayısını ve hesaplama karmaşıklığını kontrol etmeye yardımcı olurken, başlangıç parametrelerinin önemli özellikleri öğrenmesini sağlar.
> Pooling katmanından önceki konvolüsyonları, giriş verilerinden özellikleri çıkarmanın bir yolu olarak görebilirsiniz (çizgiler, kenarlar gibi), bu bilgi hala havuzlanmış çıktıda mevcut olacaktır, ancak bir sonraki konvolüsyon katmanı orijinal giriş verilerini göremeyecek, yalnızca bu bilginin azaltılmış versiyonu olan havuzlanmış çıktıyı görecektir.
> Genellikle şu sırayla: `Conv → ReLU → Pool`, her 2×2 havuzlama penceresi artık özellik aktivasyonlarıyla (“kenar mevcut / yok”) rekabet eder, ham piksel yoğunluklarıyla değil. En güçlü aktivasyonu korumak, gerçekten de en belirgin kanıtı korur.

Sonra, ihtiyaç duyulan kadar konvolüsyon ve pooling katmanı ekledikten sonra, çıktıyı tamamen bağlı katmanlara beslemek için düzleştirebiliriz. Bu, tensörü her örnek için 1D vektör haline getirerek yapılır:
```python
x = x.view(-1, 64*24*24)
```
Ve önceki konvolüsyonel ve havuzlama katmanları tarafından üretilen tüm eğitim parametreleriyle bu 1D vektörle, tam bağlantılı bir katmanı şu şekilde tanımlayabiliriz:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Önceki katmanın düzleştirilmiş çıktısını alacak ve bunu 512 gizli birime haritalayacaktır.

Bu katmanın `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` eğitilebilir parametre eklediğine dikkat edin; bu, konvolüsyonel katmanlara kıyasla önemli bir artıştır. Bunun nedeni, tam bağlantılı katmanların bir katmandaki her nöronu bir sonraki katmandaki her nörona bağlamasıdır, bu da büyük bir parametre sayısına yol açar.

Son olarak, nihai sınıf logitlerini üretmek için bir çıkış katmanı ekleyebiliriz:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Bu, `(512 + 1 (bias)) * num_classes` eğitilebilir parametre ekleyecektir; burada `num_classes`, sınıflandırma görevindeki sınıf sayısını ifade eder (örneğin, GTSRB veri seti için 43).

Son yaygın uygulamalardan biri, aşırı uyumu önlemek için tam bağlantılı katmanlardan önce bir dropout katmanı eklemektir. Bu, şu şekilde yapılabilir:
```python
self.dropout = nn.Dropout(0.5)
```
Bu katman, eğitim sırasında giriş birimlerinin bir kısmını rastgele sıfıra ayarlar; bu, belirli nöronlara olan bağımlılığı azaltarak aşırı uyumu önlemeye yardımcı olur.

### CNN Kod örneği
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
### CNN Kod eğitim örneği

Aşağıdaki kod, bazı eğitim verileri oluşturacak ve yukarıda tanımlanan `MY_NET` modelini eğitecektir. Dikkate değer bazı ilginç değerler:

- `EPOCHS`, modelin eğitim sırasında tüm veri kümesini göreceği kezdir. EPOCH çok küçükse, model yeterince öğrenemeyebilir; çok büyükse, aşırı uyum sağlayabilir.
- `LEARNING_RATE`, optimizasyon için adım boyutudur. Küçük bir öğrenme oranı yavaş yakınsama ile sonuçlanabilirken, büyük bir oran optimal çözümü aşabilir ve yakınsamayı engelleyebilir.
- `WEIGHT_DECAY`, büyük ağırlıkları cezalandırarak aşırı uyumu önlemeye yardımcı olan bir düzenleme terimidir.

Eğitim döngüsü ile ilgili bilmeniz gereken bazı ilginç bilgiler:
- `criterion = nn.CrossEntropyLoss()` çok sınıflı sınıflandırma görevleri için kullanılan kayıp fonksiyonudur. Softmax aktivasyonu ve çapraz entropi kaybını tek bir fonksiyonda birleştirerek, sınıf logitleri üreten modellerin eğitimi için uygun hale getirir.
- Modelin ikili sınıflandırma veya regresyon gibi diğer türde çıktılar üretmesi bekleniyorsa, ikili sınıflandırma için `nn.BCEWithLogitsLoss()` veya regresyon için `nn.MSELoss()` gibi farklı kayıp fonksiyonları kullanırdık.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` Adam optimizasyonunu başlatır; bu, derin öğrenme modellerini eğitmek için popüler bir tercihtir. Öğrenme oranını, gradyanların birinci ve ikinci momentlerine göre her parametre için uyarlamaktadır.
- `optim.SGD` (Stokastik Gradyan İnişi) veya `optim.RMSprop` gibi diğer optimizatörler de, eğitim görevlerinin özel gereksinimlerine bağlı olarak kullanılabilir.
- `model.train()` metodu, modeli eğitim moduna ayarlar ve dropout ve batch normalization gibi katmanların eğitim sırasında değerlendirmeden farklı davranmasını sağlar.
- `optimizer.zero_grad()` geri yayılmadan önce tüm optimize edilen tensörlerin gradyanlarını temizler; bu, PyTorch'ta gradyanların varsayılan olarak biriktiği için gereklidir. Temizlenmezse, önceki iterasyonlardan gelen gradyanlar mevcut gradyanlara eklenir ve yanlış güncellemelerle sonuçlanır.
- `loss.backward()` kaybın model parametrelerine göre gradyanlarını hesaplar; bu gradyanlar daha sonra optimizatör tarafından ağırlıkları güncellemek için kullanılır.
- `optimizer.step()` hesaplanan gradyanlar ve öğrenme oranına dayanarak model parametrelerini günceller.
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
## Tekrarlayan Sinir Ağları (RNN'ler)

Tekrarlayan Sinir Ağları (RNN'ler), zaman serileri veya doğal dil gibi sıralı verileri işlemek için tasarlanmış bir sinir ağı sınıfıdır. Geleneksel ileri beslemeli sinir ağlarının aksine, RNN'ler kendilerine geri dönen bağlantılara sahiptir, bu da onlara dizideki önceki girdiler hakkında bilgi tutan gizli bir durum sürdürme imkanı tanır.

RNN'lerin ana bileşenleri şunlardır:
- **Tekrarlayan Katmanlar**: Bu katmanlar, giriş dizilerini bir zaman adımında bir kez işleyerek, mevcut girdi ve önceki gizli duruma dayanarak gizli durumlarını günceller. Bu, RNN'lerin verideki zamansal bağımlılıkları öğrenmesine olanak tanır.
- **Gizli Durum**: Gizli durum, önceki zaman adımlarından gelen bilgileri özetleyen bir vektördür. Her zaman adımında güncellenir ve mevcut girdi için tahminler yapmakta kullanılır.
- **Çıktı Katmanı**: Çıktı katmanı, gizli duruma dayanarak nihai tahminleri üretir. Birçok durumda, RNN'ler çıktının bir dizideki bir sonraki kelime üzerindeki olasılık dağılımı olduğu dil modelleme gibi görevler için kullanılır.

Örneğin, bir dil modelinde, RNN bir kelime dizisini işler, örneğin, "Kedi" ve önceki kelimelerin sağladığı bağlama dayanarak bir sonraki kelimeyi tahmin eder, bu durumda "halı".

### Uzun Kısa Süreli Bellek (LSTM) ve Kapılı Tekrarlayan Birim (GRU)

RNN'ler, dil modelleme, makine çevirisi ve konuşma tanıma gibi sıralı verilerle ilgili görevler için özellikle etkilidir. Ancak, **uzun menzilli bağımlılıklar ile ilgili sorunlar nedeniyle zayıflayabilmektedirler**.

Bunu ele almak için, Uzun Kısa Süreli Bellek (LSTM) ve Kapılı Tekrarlayan Birim (GRU) gibi özel mimariler geliştirilmiştir. Bu mimariler, bilgiyi kontrol eden kapama mekanizmaları tanıtarak uzun menzilli bağımlılıkları daha etkili bir şekilde yakalamalarına olanak tanır.

- **LSTM**: LSTM ağları, hücre durumuna bilgi akışını düzenlemek için üç kapı (giriş kapısı, unutma kapısı ve çıkış kapısı) kullanır ve uzun diziler boyunca bilgiyi hatırlama veya unutma yeteneği sağlar. Giriş kapısı, mevcut girdi ve önceki gizli duruma dayanarak ne kadar yeni bilgi ekleyeceğini kontrol eder, unutma kapısı ise ne kadar bilgiyi atacağını kontrol eder. Giriş kapısı ve unutma kapısını birleştirerek yeni durumu elde ederiz. Son olarak, yeni hücre durumunu, giriş ve önceki gizli durum ile birleştirerek yeni gizli durumu elde ederiz.
- **GRU**: GRU ağları, LSTM mimarisini giriş ve unutma kapılarını tek bir güncelleme kapısında birleştirerek basitleştirir, bu da onları hesaplama açısından daha verimli hale getirirken uzun menzilli bağımlılıkları yakalamaya devam eder.

## LLM'ler (Büyük Dil Modelleri)

Büyük Dil Modelleri (LLM'ler), doğal dil işleme görevleri için özel olarak tasarlanmış bir derin öğrenme modeli türüdür. Büyük miktarda metin verisi üzerinde eğitilirler ve insan benzeri metinler üretebilir, soruları yanıtlayabilir, dilleri çevirebilir ve çeşitli diğer dil ile ilgili görevleri yerine getirebilirler. LLM'ler genellikle, bir dizideki kelimeler arasındaki ilişkileri yakalamak için kendine dikkat mekanizmaları kullanan dönüştürücü mimarilere dayanır, bu da bağlamı anlamalarına ve tutarlı metinler üretmelerine olanak tanır.

### Dönüştürücü Mimarisi
Dönüştürücü mimarisi, birçok LLM'nin temelini oluşturur. Giriş dizisini işleyen bir kodlayıcı-çözücü yapısından oluşur ve çözücü çıktı dizisini üretir. Dönüştürücü mimarisinin ana bileşenleri şunlardır:
- **Kendine Dikkat Mekanizması**: Bu mekanizma, modelin temsil oluştururken bir dizideki farklı kelimelerin önemini tartmasına olanak tanır. Kelimeler arasındaki ilişkilere dayanarak dikkat puanları hesaplar, bu da modelin ilgili bağlama odaklanmasını sağlar.
- **Çoklu Başlı Dikkat**: Bu bileşen, modelin birden fazla dikkat başlığı kullanarak kelimeler arasındaki birden fazla ilişkiyi yakalamasına olanak tanır; her başlık, girişin farklı yönlerine odaklanır.
- **Pozisyonel Kodlama**: Dönüştürücüler, kelime sırası hakkında yerleşik bir kavrama sahip olmadığından, dizideki kelimelerin konumuna dair bilgi sağlamak için giriş gömme katmanlarına pozisyonel kodlama eklenir.

## Difüzyon Modelleri
Difüzyon modelleri, bir difüzyon sürecini simüle ederek veri üretmeyi öğrenen bir üretken model sınıfıdır. Görüntü üretimi gibi görevler için özellikle etkilidirler ve son yıllarda popülerlik kazanmışlardır. Difüzyon modelleri, basit bir gürültü dağılımını karmaşık bir veri dağılımına dönüştürmek için bir dizi difüzyon adımı aracılığıyla çalışır. Difüzyon modellerinin ana bileşenleri şunlardır:
- **İleri Difüzyon Süreci**: Bu süreç, veriye gürültü ekleyerek onu basit bir gürültü dağılımına dönüştürür. İleri difüzyon süreci genellikle, her seviye belirli bir miktarda gürültü eklenmesini temsil eden bir dizi gürültü seviyesi ile tanımlanır.
- **Ters Difüzyon Süreci**: Bu süreç, ileri difüzyon sürecini tersine çevirmeyi öğrenir, veriyi yavaş yavaş gürültüden arındırarak hedef dağılımdan örnekler üretir. Ters difüzyon süreci, modelin gürültülü örneklerden orijinal veriyi yeniden oluşturmasını teşvik eden bir kayıp fonksiyonu kullanılarak eğitilir.

Ayrıca, bir metin isteminden bir görüntü üretmek için, difüzyon modelleri genellikle şu adımları izler:
1. **Metin Kodlama**: Metin istemi, bir metin kodlayıcı (örneğin, bir dönüştürücü tabanlı model) kullanılarak gizli bir temsile kodlanır. Bu temsil, metnin anlamsal anlamını yakalar.
2. **Gürültü Örnekleme**: Bir Gauss dağılımından rastgele bir gürültü vektörü örneklenir.
3. **Difüzyon Adımları**: Model, gürültü vektörünü metin istemine karşılık gelen bir görüntüye dönüştürmek için bir dizi difüzyon adımı uygular. Her adım, görüntüyü gürültüden arındırmak için öğrenilen dönüşümleri uygulamayı içerir.

{{#include ../banners/hacktricks-training.md}}
