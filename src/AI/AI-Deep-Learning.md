# Глибоке навчання

{{#include ../banners/hacktricks-training.md}}

## Глибоке навчання <sup>[[1]](#references)</sup>

Глибоке навчання є підмножиною машинного навчання, яка використовує нейронні мережі з кількома шарами (глибокі нейронні мережі) для моделювання складних закономірностей у даних. Воно досягло визначних успіхів у різних галузях, зокрема в комп'ютерному зорі, обробці природної мови та розпізнаванні мовлення.

### Нейронні мережі

Нейронні мережі є будівельними блоками deep learning. Вони складаються зі з'єднаних між собою вузлів (нейронів), організованих у шари. Кожен нейрон отримує вхідні дані, застосовує зважену суму та передає результат через функцію активації для отримання вихідного значення. Шари можна класифікувати так:
- **Вхідний шар**: Перший шар, який отримує вхідні дані.
- **Приховані шари**: Проміжні шари, які виконують перетворення вхідних даних. Кількість прихованих шарів і нейронів у кожному шарі може відрізнятися, що призводить до різних архітектур.
- **Вихідний шар**: Останній шар, який формує вихід мережі, наприклад імовірності класів у завданнях класифікації.


### Функції активації

Коли шар нейронів обробляє вхідні дані, кожен нейрон застосовує вагу та зміщення до входу (`z = w * x + b`), де `w` — вага, `x` — вхідне значення, а `b` — зміщення. Потім вихід нейрона передається через **функцію активації, щоб додати нелінійність** до моделі. Ця функція активації фактично вказує, чи «має бути активований наступний нейрон і наскільки». Це дає мережі змогу вивчати складні закономірності та взаємозв'язки в даних, завдяки чому вона може апроксимувати будь-яку неперервну функцію.

Отже, функції активації додають нелінійність до нейронної мережі, даючи їй змогу вивчати складні взаємозв'язки в даних. До поширених функцій активації належать:
- **Sigmoid**: Відображає вхідні значення в діапазон від 0 до 1 і часто використовується у бінарній класифікації.
- **ReLU (Rectified Linear Unit)**: Безпосередньо повертає вхідне значення, якщо воно додатне; інакше повертає нуль. Широко використовується завдяки простоті та ефективності під час навчання глибоких мереж.
- **Tanh**: Відображає вхідні значення в діапазон від -1 до 1 і часто використовується у прихованих шарах.
- **Softmax**: Перетворює необроблені оцінки на ймовірності й часто використовується у вихідному шарі для багатокласової класифікації.

### Backpropagation

Backpropagation — це алгоритм, який використовується для навчання нейронних мереж шляхом коригування ваг з'єднань між нейронами. Він працює шляхом обчислення градієнта функції втрат відносно кожної ваги та оновлення ваг у напрямку, протилежному градієнту, щоб мінімізувати втрати. Backpropagation складається з таких кроків:

1. **Прямий прохід**: Обчислити вихід мережі, передавши вхідні дані через шари та застосувавши функції активації.
2. **Обчислення втрат**: Обчислити втрати (помилку) між передбаченим виходом і правильним цільовим значенням за допомогою функції втрат (наприклад, середньоквадратичної помилки для регресії або cross-entropy для класифікації).
3. **Зворотний прохід**: Обчислити градієнти втрат відносно кожної ваги, використовуючи chain rule диференціального числення.
4. **Оновлення ваг**: Оновити ваги за допомогою алгоритму оптимізації (наприклад, stochastic gradient descent або Adam), щоб мінімізувати втрати.

## Згорткові нейронні мережі (CNNs) <sup>[[2]](#references)</sup>

Згорткові нейронні мережі (CNNs) — це спеціалізований тип нейронних мереж, призначений для обробки даних у формі сітки, наприклад зображень. Вони особливо ефективні в завданнях комп'ютерного зору завдяки здатності автоматично вивчати просторові ієрархії ознак.

Основні компоненти CNNs:
- **Згорткові шари**: Застосовують операції згортки до вхідних даних за допомогою навчуваних фільтрів (ядер) для вилучення локальних ознак. Кожен фільтр переміщується по входу та обчислює скалярний добуток, формуючи карту ознак.
- **Шари pooling**: Зменшують розмір карт ознак, зберігаючи важливі ознаки. Поширені операції pooling включають max pooling та average pooling.
- **Повнозв'язані шари**: З'єднують кожен нейрон одного шару з кожним нейроном наступного шару, подібно до традиційних нейронних мереж. Зазвичай ці шари використовуються наприкінці мережі для завдань класифікації.

У межах **`Convolutional Layers`** CNNs також можна розрізнити:
- **Початковий згортковий шар**: Перший згортковий шар, який обробляє необроблені вхідні дані (наприклад, зображення) і використовується для визначення базових ознак, таких як краї та текстури.
- **Проміжні згорткові шари**: Наступні згорткові шари, які розвивають ознаки, вивчені початковим шаром, даючи мережі змогу вивчати складніші закономірності та представлення.
- **Останній згортковий шар**: Останні згорткові шари перед повнозв'язаними шарами, які захоплюють високорівневі ознаки та готують дані до класифікації.

> [!TIP]
> CNNs особливо ефективні для завдань класифікації зображень, виявлення об'єктів і сегментації зображень завдяки здатності вивчати просторові ієрархії ознак у даних у формі сітки та зменшувати кількість параметрів за допомогою спільного використання ваг.
> Крім того, вони краще працюють із даними, що підтримують принцип локальності ознак, за якого сусідні дані (пікселі) з більшою ймовірністю пов'язані між собою, ніж віддалені пікселі; для інших типів даних, наприклад тексту, це може бути не так.
> Також зверніть увагу, що CNNs можуть визначати навіть складні ознаки, але не здатні застосовувати просторовий контекст, тобто одна й та сама ознака, знайдена в різних частинах зображення, буде однаковою.

### Приклад визначення CNN

*Тут наведено опис того, як визначити згорткову нейронну мережу (CNN) у PyTorch, яка починає з batch RGB-зображень як dataset розміром 48x48 і використовує згорткові шари та maxpool для вилучення ознак, після чого застосовує повнозв'язані шари для класифікації.*

Ось як можна визначити 1 згортковий шар у PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Кількість вхідних каналів. Для RGB-зображень це 3 (по одному для кожного колірного каналу). Якщо ви працюєте із зображеннями у відтінках сірого, це значення дорівнюватиме 1.

- `out_channels`: Кількість вихідних каналів (фільтрів), які вивчатиме згортковий шар. Це гіперпараметр, який можна налаштувати залежно від архітектури моделі.

- `kernel_size`: Розмір згорткового фільтра. Поширеним варіантом є 3x3, що означає, що фільтр охоплюватиме область 3x3 вхідного зображення. Це схоже на кольоровий штамп розміром 3×3×3, який використовується для формування out_channels із in_channels:
1. Розмістіть цей штамп 3×3×3 у верхньому лівому куті куба зображення.
2. Помножте кожну вагу на піксель під нею, складіть усі значення та додайте bias → ви отримаєте одне число.
3. Запишіть це число в порожню карту в позиції (0, 0).
4. Перемістіть штамп на один піксель праворуч (stride = 1) і повторюйте, доки не заповните всю сітку 48×48.

- `padding`: Кількість пікселів, доданих до кожної сторони входу. Padding допомагає зберегти просторові розміри входу, забезпечуючи більший контроль над розміром виходу. Наприклад, для ядра 3x3 і вхідного зображення розміром 48x48 пікселів padding зі значенням 1 збереже такий самий розмір виходу (48x48) після операції згортки. Це відбувається тому, що padding додає межу завширшки 1 піксель навколо вхідного зображення, даючи змогу ядру переміщуватися по краях без зменшення просторових розмірів.

Отже, кількість trainable параметрів у цьому шарі становить:
- (3x3x3 (розмір ядра) + 1 (bias)) x 32 (out_channels) = 896 trainable параметрів.

Зверніть увагу, що для кожного використаного ядра додається Bias (+1), оскільки функція кожного згорткового шару полягає у вивченні лінійного перетворення входу, яке представляється рівнянням:
```plaintext
Y = f(W * X + b)
```
де `W` — матриця ваг (вивчені фільтри, 3x3x3 = 27 параметрів), а `b` — вектор зміщення, значення якого дорівнює +1 для кожного вихідного каналу.

Зверніть увагу, що результатом роботи `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` буде tensor форми `(batch_size, 32, 48, 48)`, оскільки 32 — це нова кількість згенерованих каналів розміром 48x48 пікселів.

Потім ми можемо під'єднати цей згортковий шар до іншого згорткового шару, наприклад: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Це додасть: (32x3x3 (розмір ядра) + 1 (зміщення)) x 64 (out_channels) = 18,496 параметрів, що навчаються, а також результат форми `(batch_size, 64, 48, 48)`.

Як бачите, **кількість параметрів швидко зростає з кожним додатковим згортковим шаром**, особливо зі збільшенням кількості вихідних каналів.

Один зі способів контролювати обсяг використовуваних даних — застосовувати **max pooling** після кожного згорткового шару. Max pooling зменшує просторові розміри feature maps, що допомагає зменшити кількість параметрів і обчислювальну складність, зберігаючи важливі features.

Його можна оголосити так: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Це означає використання сітки розміром 2x2 пікселі та вибір максимального значення з кожної сітки для зменшення розміру feature map удвічі. Крім того, `stride=2` означає, що операція pooling переміщуватиметься на 2 пікселі за раз, у цьому випадку запобігаючи будь-якому перекриттю між областями pooling.

Після додавання цього pooling layer форма результату після першого згорткового шару буде `(batch_size, 64, 24, 24)` після застосування `self.pool1` до результату `self.conv2`, що зменшить розмір до 1/4 розміру попереднього шару.

> [!TIP]
> Важливо застосовувати pooling після згорткових шарів, щоб зменшити просторові розміри feature maps. Це допомагає контролювати кількість параметрів і обчислювальну складність, водночас даючи початковим параметрам змогу навчатися важливих features.
>Ви можете розглядати згортки перед pooling layer як спосіб вилучення features із вхідних даних (наприклад, ліній і країв). Ця інформація все ще буде присутня у pooled output, але наступний згортковий шар уже не зможе бачити початкові вхідні дані — лише pooled output, який є зменшеною версією попереднього шару з цією інформацією.
>У типовому порядку: `Conv → ReLU → Pool` кожне вікно pooling розміром 2×2 взаємодіє з активаціями features («край присутній / відсутній»), а не з необробленими значеннями пікселів. Збереження найсильнішої активації справді зберігає найбільш важливі ознаки.

Після додавання необхідної кількості згорткових і pooling layers ми можемо вирівняти результат, щоб передати його до fully connected layers. Для цього tensor переформатується в 1D-вектор для кожного зразка в batch:
```python
x = x.view(-1, 64*24*24)
```
І за допомогою цього 1D-вектора з усіма параметрами навчання, згенерованими попередніми convolutional і pooling шарами, ми можемо визначити fully connected layer так:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Який візьме сплощений вихід попереднього шару та зіставить його з 512 прихованими блоками.

Зверніть увагу, що цей шар додав `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` trainable parameters, що є значним збільшенням порівняно зі згортковими шарами. Це пояснюється тим, що fully connected layers з'єднують кожен нейрон одного шару з кожним нейроном наступного шару, що призводить до великої кількості параметрів.

Нарешті, ми можемо додати вихідний шар для отримання фінальних class logits:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Це додасть `(512 + 1 (bias)) * num_classes` trainable параметрів, де `num_classes` — кількість класів у завданні класифікації (наприклад, 43 для набору даних GTSRB).

Ще одна поширена практика — додати dropout layer перед fully connected layers, щоб запобігти overfitting. Це можна зробити за допомогою:
```python
self.dropout = nn.Dropout(0.5)
```
Цей шар випадково встановлює частину вхідних блоків у нуль під час навчання, що допомагає запобігти перенавчанню, зменшуючи залежність від конкретних нейронів.

### Приклад коду CNN
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
### Приклад навчання CNN Code

Наведений нижче код створить деякі навчальні дані та навчить модель `MY_NET`, визначену вище. Варто звернути увагу на такі значення:

- `EPOCHS` — кількість разів, протягом яких модель побачить увесь набір даних під час навчання. Якщо EPOCH має надто мале значення, модель може навчитися недостатньо; якщо надто велике — вона може перенавчитися.
- `LEARNING_RATE` — розмір кроку для optimizer. Малий learning rate може призвести до повільної сходимості, тоді як великий може перевищити оптимальне рішення та перешкодити сходимості.
- `WEIGHT_DECAY` — термін regularization, який допомагає запобігти перенавчанню, штрафуючи великі ваги.

Щодо циклу навчання, варто знати таку інформацію:
- `criterion = nn.CrossEntropyLoss()` — функція втрат, яка використовується для задач багатокласової класифікації. Вона поєднує softmax activation і cross-entropy loss в одній функції, що робить її придатною для навчання моделей, які повертають class logits.
- Якщо очікувалося, що модель повертатиме інші типи результатів, наприклад для бінарної класифікації або regression, ми використовували б інші функції втрат, як-от `nn.BCEWithLogitsLoss()` для бінарної класифікації або `nn.MSELoss()` для regression.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` ініціалізує Adam optimizer, який є популярним вибором для навчання deep learning моделей. Він адаптує learning rate для кожного параметра на основі першого та другого моментів градієнтів.
- Також можна використовувати інші optimizers, як-от `optim.SGD` (Stochastic Gradient Descent) або `optim.RMSprop`, залежно від конкретних вимог до задачі навчання.
- Метод `model.train()` переводить модель у режим навчання, завдяки чому такі шари, як dropout і batch normalization, працюють інакше під час навчання, ніж під час evaluation.
- `optimizer.zero_grad()` очищає градієнти всіх оптимізованих тензорів перед backward pass. Це необхідно, оскільки в PyTorch градієнти за замовчуванням накопичуються. Якщо їх не очищати, градієнти з попередніх ітерацій додаватимуться до поточних, що призводитиме до неправильних оновлень.
- `loss.backward()` обчислює градієнти втрат відносно параметрів моделі, які потім використовуються optimizer для оновлення ваг.
- `optimizer.step()` оновлює параметри моделі на основі обчислених градієнтів і learning rate.
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
## Рекурентні нейронні мережі (RNNs) <sup>[[3]](#references)</sup>

Рекурентні нейронні мережі (RNNs) — це клас нейронних мереж, призначених для обробки послідовних даних, таких як часові ряди або природна мова. На відміну від традиційних нейронних мереж прямого поширення, RNNs мають з'єднання, які зациклюються самі на собі, що дає їм змогу підтримувати прихований стан, який зберігає інформацію про попередні вхідні дані в послідовності.

Основні компоненти RNNs:
- **Рекурентні шари**: ці шари обробляють вхідні послідовності по одному часовому кроку, оновлюючи свій прихований стан на основі поточного входу та попереднього прихованого стану. Це дає змогу RNNs навчатися часових залежностей у даних.
- **Прихований стан**: прихований стан — це вектор, який узагальнює інформацію з попередніх часових кроків. Він оновлюється на кожному часовому кроці та використовується для прогнозування поточного входу.
- **Вихідний шар**: вихідний шар створює остаточні прогнози на основі прихованого стану. У багатьох випадках RNNs використовуються для таких завдань, як мовне моделювання, де вихідними даними є розподіл імовірностей для наступного слова в послідовності.

Наприклад, у мовній моделі RNN обробляє послідовність слів, наприклад "The cat sat on the", і прогнозує наступне слово на основі контексту, наданого попередніми словами, у цьому випадку — "mat".

### Довготривала короткочасна пам'ять (LSTM) і вентильний рекурентний блок (GRU) <sup>[[3]](#references)</sup>

RNNs особливо ефективні для завдань, що включають послідовні дані, таких як мовне моделювання, машинний переклад і розпізнавання мовлення. Однак вони можуть мати труднощі з **довготривалими залежностями через такі проблеми, як зникаючі градієнти**.

Для вирішення цієї проблеми були розроблені спеціалізовані архітектури, такі як Long Short-Term Memory (LSTM) і Gated Recurrent Unit (GRU). Ці архітектури вводять механізми вентилів, які керують потоком інформації, даючи їм змогу ефективніше виявляти довготривалі залежності.

- **LSTM**: мережі LSTM використовують три вентилі (вхідний вентиль, вентиль забування та вихідний вентиль) для регулювання потоку інформації в стан клітинки та з нього, що дає їм змогу запам'ятовувати або забувати інформацію протягом довгих послідовностей. Вхідний вентиль контролює, який обсяг нової інформації додати на основі входу та попереднього прихованого стану, а вентиль забування контролює, який обсяг інформації відкинути. Поєднуючи вхідний вентиль і вентиль забування, ми отримуємо новий стан. Нарешті, поєднуючи новий стан клітинки з входом і попереднім прихованим станом, ми також отримуємо новий прихований стан.
- **GRU**: мережі GRU спрощують архітектуру LSTM, поєднуючи вхідний вентиль і вентиль забування в один вентиль оновлення, що робить їх обчислювально ефективнішими, водночас зберігаючи здатність виявляти довготривалі залежності.

## LLMs (Великі мовні моделі)

Великі мовні моделі (LLMs) — це тип моделей глибокого навчання, спеціально призначених для завдань обробки природної мови. Вони навчаються на величезних обсягах текстових даних і можуть генерувати текст, схожий на створений людиною, відповідати на запитання, перекладати мови та виконувати різноманітні інші завдання, пов'язані з мовою.
LLMs зазвичай базуються на архітектурах transformer, які використовують механізми self-attention для виявлення зв'язків між словами в послідовності, що дає їм змогу розуміти контекст і генерувати зв'язний текст.

### Архітектура Transformer <sup>[[4]](#references)</sup>
Архітектура transformer є основою багатьох LLMs. Вона складається зі структури encoder-decoder, де encoder обробляє вхідну послідовність, а decoder генерує вихідну послідовність. Основні компоненти архітектури transformer:
- **Механізм Self-Attention**: цей механізм дає змогу моделі оцінювати важливість різних слів у послідовності під час створення представлень. Він обчислює оцінки attention на основі зв'язків між словами, даючи змогу моделі зосереджуватися на релевантному контексті.
- **Multi-Head Attention**: цей компонент дає змогу моделі виявляти численні зв'язки між словами за допомогою кількох attention heads, кожна з яких зосереджується на різних аспектах входу.
- **Positional Encoding**: оскільки transformers не мають вбудованого уявлення про порядок слів, positional encoding додається до вхідних embedding, щоб надати інформацію про позицію слів у послідовності.

## Diffusion Models <sup>[[5]](#references)</sup>
Diffusion models — це клас генеративних моделей, які навчаються генерувати дані шляхом симуляції процесу дифузії. Вони особливо ефективні для таких завдань, як генерація зображень, і набули популярності в останні роки.
Diffusion models працюють шляхом поступового перетворення простого розподілу шуму на складний розподіл даних через низку кроків дифузії. Основні компоненти diffusion models:
- **Прямий процес дифузії**: цей процес поступово додає шум до даних, перетворюючи їх на простий розподіл шуму. Прямий процес дифузії зазвичай визначається низкою рівнів шуму, де кожен рівень відповідає певній кількості шуму, доданого до даних.
- **Зворотний процес дифузії**: цей процес навчається обертати прямий процес дифузії, поступово усуваючи шум із даних для генерування зразків цільового розподілу. Зворотний процес дифузії навчається за допомогою функції втрат, яка спонукає модель відновлювати вихідні дані з зашумлених зразків.

Крім того, щоб генерувати зображення з текстового prompt, diffusion models зазвичай виконують такі кроки:
1. **Кодування тексту**: текстовий prompt кодується в латентне представлення за допомогою text encoder (наприклад, моделі на основі transformer). Це представлення передає семантичне значення тексту.
2. **Вибірка шуму**: випадковий вектор шуму вибирається з гауссового розподілу.
3. **Кроки дифузії**: модель застосовує низку кроків дифузії, поступово перетворюючи вектор шуму на зображення, що відповідає текстовому prompt. Кожен крок передбачає застосування навчених перетворень для усунення шуму із зображення.

## References

- [1] [PyTorch - Посібник з нейронних мереж](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Ймовірнісні моделі дифузії з усуненням шуму](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
