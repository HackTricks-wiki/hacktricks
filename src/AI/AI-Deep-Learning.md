# Głębokie uczenie

{{#include ../banners/hacktricks-training.md}}

## Głębokie uczenie <sup>[[1]](#references)</sup>

Głębokie uczenie jest podzbiorem machine learning, który wykorzystuje sieci neuronowe z wieloma warstwami (głębokie sieci neuronowe) do modelowania złożonych wzorców w danych. Osiągnęło ono znaczące sukcesy w różnych dziedzinach, w tym w computer vision, przetwarzaniu języka naturalnego i rozpoznawaniu mowy.

### Sieci neuronowe

Sieci neuronowe są podstawowymi elementami deep learning. Składają się z połączonych ze sobą węzłów (neuronów) zorganizowanych w warstwy. Każdy neuron otrzymuje dane wejściowe, oblicza sumę ważoną i przekazuje wynik przez funkcję aktywacji, aby wygenerować dane wyjściowe. Warstwy można podzielić w następujący sposób:
- **Warstwa wejściowa**: Pierwsza warstwa, która otrzymuje dane wejściowe.
- **Warstwy ukryte**: Warstwy pośrednie, które wykonują transformacje danych wejściowych. Liczba warstw ukrytych i neuronów w każdej warstwie może się różnić, prowadząc do powstania różnych architektur.
- **Warstwa wyjściowa**: Ostatnia warstwa, która generuje dane wyjściowe sieci, takie jak prawdopodobieństwa klas w zadaniach klasyfikacji.


### Funkcje aktywacji

Gdy warstwa neuronów przetwarza dane wejściowe, każdy neuron stosuje wagę i bias do danych wejściowych (`z = w * x + b`), gdzie `w` jest wagą, `x` jest danymi wejściowymi, a `b` jest biasem. Dane wyjściowe neuronu są następnie przekazywane przez **funkcję aktywacji w celu wprowadzenia nieliniowości** do modelu. Ta funkcja aktywacji zasadniczo wskazuje, czy następny neuron „powinien zostać aktywowany i w jakim stopniu”. Dzięki temu sieć może uczyć się złożonych wzorców i zależności w danych, co umożliwia jej aproksymowanie dowolnej funkcji ciągłej.

Funkcje aktywacji wprowadzają zatem nieliniowość do sieci neuronowej, umożliwiając jej uczenie się złożonych zależności w danych. Typowe funkcje aktywacji obejmują:
- **Sigmoid**: Odwzorowuje wartości wejściowe na zakres od 0 do 1; często używana w klasyfikacji binarnej.
- **ReLU (Rectified Linear Unit)**: Zwraca dane wejściowe bezpośrednio, jeśli są dodatnie; w przeciwnym razie zwraca zero. Jest szeroko stosowana ze względu na prostotę i skuteczność w trenowaniu głębokich sieci.
- **Tanh**: Odwzorowuje wartości wejściowe na zakres od -1 do 1; często używana w warstwach ukrytych.
- **Softmax**: Konwertuje surowe wyniki na prawdopodobieństwa; często używana w warstwie wyjściowej do klasyfikacji wieloklasowej.

### Backpropagation

Backpropagation to algorytm używany do trenowania sieci neuronowych poprzez dostosowywanie wag połączeń między neuronami. Działa poprzez obliczanie gradientu funkcji straty względem każdej wagi i aktualizowanie wag w kierunku przeciwnym do gradientu w celu zminimalizowania straty. Kroki wykonywane podczas backpropagation to:

1. **Forward Pass**: Obliczenie danych wyjściowych sieci poprzez przekazanie danych wejściowych przez warstwy i zastosowanie funkcji aktywacji.
2. **Loss Calculation**: Obliczenie straty (błędu) między przewidywanymi danymi wyjściowymi a prawdziwą wartością docelową za pomocą funkcji straty (np. średni błąd kwadratowy dla regresji, cross-entropy dla klasyfikacji).
3. **Backward Pass**: Obliczenie gradientów straty względem każdej wagi przy użyciu reguły łańcuchowej rachunku różniczkowego.
4. **Weight Update**: Aktualizacja wag za pomocą algorytmu optymalizacji (np. stochastic gradient descent, Adam) w celu zminimalizowania straty.

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Convolutional Neural Networks (CNNs) to wyspecjalizowany typ sieci neuronowej przeznaczony do przetwarzania danych o strukturze siatki, takich jak obrazy. Są szczególnie skuteczne w zadaniach computer vision ze względu na zdolność do automatycznego uczenia się przestrzennych hierarchii cech.

Główne komponenty CNN obejmują:
- **Convolutional Layers**: Stosują operacje splotu na danych wejściowych za pomocą uczonych filtrów (jąder) w celu wyodrębnienia cech lokalnych. Każdy filtr przesuwa się po danych wejściowych i oblicza iloczyn skalarny, tworząc mapę cech.
- **Pooling Layers**: Zmniejszają mapy cech, aby ograniczyć ich wymiary przestrzenne przy jednoczesnym zachowaniu istotnych cech. Typowe operacje pooling obejmują max pooling i average pooling.
- **Fully Connected Layers**: Łączą każdy neuron jednej warstwy z każdym neuronem następnej warstwy, podobnie jak w tradycyjnych sieciach neuronowych. Warstwy te są zwykle używane na końcu sieci do zadań klasyfikacyjnych.

Wewnątrz CNN, w **`Convolutional Layers`**, możemy również wyróżnić:
- **Initial Convolutional Layer**: Pierwsza warstwa splotowa, która przetwarza surowe dane wejściowe (np. obraz) i jest przydatna do identyfikowania podstawowych cech, takich jak krawędzie i tekstury.
- **Intermediate Convolutional Layers**: Kolejne warstwy splotowe, które bazują na cechach wyuczonych przez warstwę początkową, umożliwiając sieci uczenie się bardziej złożonych wzorców i reprezentacji.
- **Final Convolutional Layer**: Ostatnie warstwy splotowe przed warstwami w pełni połączonymi, które przechwytują cechy wysokiego poziomu i przygotowują dane do klasyfikacji.

> [!TIP]
> CNN są szczególnie skuteczne w zadaniach klasyfikacji obrazów, wykrywania obiektów i segmentacji obrazów ze względu na zdolność do uczenia się przestrzennych hierarchii cech w danych o strukturze siatki oraz zmniejszania liczby parametrów dzięki współdzieleniu wag.
> Ponadto lepiej działają z danymi, które spełniają zasadę lokalności cech, zgodnie z którą sąsiednie dane (piksele) są bardziej prawdopodobnie powiązane niż odległe piksele, co może nie mieć miejsca w przypadku innych typów danych, takich jak tekst.
> Co więcej, należy zauważyć, że CNN będą w stanie identyfikować nawet złożone cechy, ale nie będą w stanie stosować żadnego kontekstu przestrzennego, co oznacza, że ta sama cecha znaleziona w różnych częściach obrazu będzie traktowana tak samo.

### Przykład definiowania CNN

*Tutaj znajdziesz opis sposobu definiowania Convolutional Neural Network (CNN) w PyTorch, która rozpoczyna pracę z batch’em obrazów RGB jako datasetem o rozmiarze 48x48 i wykorzystuje warstwy splotowe oraz maxpool do wyodrębniania cech, a następnie warstwy w pełni połączone do klasyfikacji.*

Tak można zdefiniować 1 warstwę splotową w PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Liczba kanałów wejściowych. W przypadku obrazów RGB wynosi ona 3 (po jednym dla każdego kanału koloru). Jeśli pracujesz z obrazami w skali szarości, będzie wynosić 1.

- `out_channels`: Liczba kanałów wyjściowych (filtrów), których nauczy się warstwa splotowa. Jest to hyperparameter, który można dostosować w zależności od architektury modelu.

- `kernel_size`: Rozmiar filtra splotowego. Typowym wyborem jest 3x3, co oznacza, że filtr obejmie obszar 3x3 obrazu wejściowego. Jest to rodzaj kolorowego stempla 3×3×3 używanego do wygenerowania `out_channels` z `in_channels`:
1. Umieść ten stempel 3×3×3 w lewym górnym rogu sześcianu obrazu.
2. Pomnóż każdą wagę przez znajdujący się pod nią piksel, dodaj wszystkie wyniki, a następnie dodaj bias → otrzymasz jedną liczbę.
3. Zapisz tę liczbę na pustej mapie w pozycji (0, 0).
4. Przesuń stempel o jeden piksel w prawo (stride = 1) i powtarzaj, aż wypełnisz całą siatkę 48×48.

- `padding`: Liczba pikseli dodawanych do każdego boku danych wejściowych. Padding pomaga zachować wymiary przestrzenne danych wejściowych, zapewniając większą kontrolę nad rozmiarem danych wyjściowych. Na przykład przy jądrze 3x3 i obrazie wejściowym o rozmiarze 48x48 pikseli padding o wartości 1 zachowa ten sam rozmiar danych wyjściowych (48x48) po operacji splotu. Dzieje się tak, ponieważ padding dodaje obramowanie o szerokości 1 piksela wokół obrazu wejściowego, umożliwiając przesuwanie jądra po krawędziach bez zmniejszania wymiarów przestrzennych.

Liczba trenowalnych parametrów w tej warstwie wynosi zatem:
- (3x3x3 (rozmiar jądra) + 1 (bias)) x 32 (`out_channels`) = 896 trenowalnych parametrów.

Należy zauważyć, że dla każdego użytego jądra dodawany jest bias (+1), ponieważ funkcją każdej warstwy splotowej jest nauczenie się liniowej transformacji danych wejściowych, reprezentowanej równaniem:
```plaintext
Y = f(W * X + b)
```
gdzie `W` jest macierzą wag (wyuczonymi filtrami, 3x3x3 = 27 parametrów), a `b` jest wektorem biasu, którego wartość dla każdego kanału wyjściowego wynosi +1.

Zauważ, że wynikiem `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` będzie tensor o kształcie `(batch_size, 32, 48, 48)`, ponieważ 32 to nowa liczba wygenerowanych kanałów o rozmiarze 48x48 pikseli.

Następnie możemy połączyć tę warstwę konwolucyjną z kolejną warstwą konwolucyjną w następujący sposób: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Doda to: (32x3x3 (rozmiar kernela) + 1 (bias)) x 64 (out_channels) = 18,496 trenowalnych parametrów oraz wynik o kształcie `(batch_size, 64, 48, 48)`.

Jak widać, **liczba parametrów szybko rośnie wraz z każdą dodatkową warstwą konwolucyjną**, szczególnie gdy zwiększa się liczba kanałów wyjściowych.

Jedną z możliwości kontrolowania ilości wykorzystywanych danych jest użycie **max pooling** po każdej warstwie konwolucyjnej. Max pooling zmniejsza przestrzenne wymiary map cech, co pomaga ograniczyć liczbę parametrów i złożoność obliczeniową, zachowując jednocześnie istotne cechy.

Można go zadeklarować jako: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Oznacza to zasadniczo użycie siatki pikseli 2x2 i wybranie maksymalnej wartości z każdej siatki w celu zmniejszenia rozmiaru mapy cech o połowę. Ponadto `stride=2` oznacza, że operacja pooling będzie przesuwać się za każdym razem o 2 piksele, co w tym przypadku zapobiega nakładaniu się obszarów poolingu.

Po użyciu tej warstwy poolingu kształt wyniku po pierwszej warstwie konwolucyjnej będzie wynosić `(batch_size, 64, 24, 24)` po zastosowaniu `self.pool1` do wyniku `self.conv2`, zmniejszając rozmiar do 1/4 rozmiaru poprzedniej warstwy.

> [!TIP]
> Ważne jest stosowanie poolingu po warstwach konwolucyjnych w celu zmniejszenia przestrzennych wymiarów map cech, co pomaga kontrolować liczbę parametrów i złożoność obliczeniową, a jednocześnie pozwala początkowym parametrom nauczyć się istotnych cech.
>Możesz postrzegać konwolucje przed warstwą poolingu jako sposób na wyodrębnianie cech z danych wejściowych (takich jak linie i krawędzie). Informacje te nadal będą obecne w wyniku poolingu, ale następna warstwa konwolucyjna nie będzie już mogła zobaczyć oryginalnych danych wejściowych, a jedynie wynik poolingu, który jest pomniejszoną wersją poprzedniej warstwy zawierającą te informacje.
>W typowej kolejności: `Conv → ReLU → Pool` każde okno poolingu 2×2 przetwarza teraz aktywacje cech („krawędź obecna / nieobecna”), a nie surowe wartości pikseli. Zachowanie najsilniejszej aktywacji rzeczywiście zachowuje najbardziej istotne informacje.

Następnie, po dodaniu tylu warstw konwolucyjnych i poolingowych, ile potrzeba, możemy spłaszczyć wynik, aby przekazać go do warstw w pełni połączonych. Robi się to przez przekształcenie tensora w wektor 1D dla każdej próbki w batchu:
```python
x = x.view(-1, 64*24*24)
```
A wraz z tym jednowymiarowym wektorem zawierającym wszystkie parametry treningowe wygenerowane przez poprzednie warstwy konwolucyjne i poolingowe możemy zdefiniować warstwę w pełni połączoną w następujący sposób:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Która pobierze spłaszczone wyjście poprzedniej warstwy i zmapuje je na 512 hidden units.

Zwróć uwagę, że ta warstwa dodała `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` trainable parameters, co stanowi znaczący wzrost w porównaniu z warstwami konwolucyjnymi. Dzieje się tak, ponieważ fully connected layers łączą każdy neuron w jednej warstwie z każdym neuronem w następnej warstwie, co prowadzi do dużej liczby parametrów.

Na koniec możemy dodać warstwę wyjściową, aby wygenerować końcowe class logits:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Doda to `(512 + 1 (bias)) * num_classes` trenowalnych parametrów, gdzie `num_classes` oznacza liczbę klas w zadaniu klasyfikacji (np. 43 dla zbioru danych GTSRB).

Inną powszechną praktyką jest dodanie warstwy dropout przed warstwami fully connected, aby zapobiec overfittingowi. Można to zrobić za pomocą:
```python
self.dropout = nn.Dropout(0.5)
```
Ta warstwa losowo ustawia ułamek jednostek wejściowych na zero podczas treningu, co pomaga zapobiegać przeuczeniu poprzez zmniejszenie zależności od określonych neuronów.

### Przykład kodu CNN
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
### Przykład treningu CNN Code

Poniższy kod utworzy dane treningowe i wytrenuje model `MY_NET` zdefiniowany powyżej. Warto zwrócić uwagę na kilka interesujących wartości:

- `EPOCHS` to liczba razy, ile model zobaczy cały zbiór danych podczas treningu. Jeśli EPOCH jest zbyt mały, model może nauczyć się zbyt mało; jeśli jest zbyt duży, może dojść do overfittingu.
- `LEARNING_RATE` to rozmiar kroku optymalizatora. Mały learning rate może prowadzić do powolnej zbieżności, podczas gdy duży może spowodować przekroczenie optymalnego rozwiązania i uniemożliwić zbieżność.
- `WEIGHT_DECAY` to termin regularyzacyjny, który pomaga zapobiegać overfittingowi poprzez nakładanie kary za duże wagi.

Jeśli chodzi o pętlę treningową, warto znać następujące informacje:
- `criterion = nn.CrossEntropyLoss()` to funkcja straty używana w zadaniach klasyfikacji wieloklasowej. Łączy aktywację softmax i stratę entropii krzyżowej w jednej funkcji, dzięki czemu nadaje się do trenowania modeli zwracających logity klas.
- Jeśli model miałby zwracać inne typy wyników, takie jak klasyfikacja binarna lub regresja, używalibyśmy innych funkcji straty, takich jak `nn.BCEWithLogitsLoss()` dla klasyfikacji binarnej lub `nn.MSELoss()` dla regresji.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inicjalizuje optymalizator Adam, który jest popularnym wyborem do trenowania modeli deep learning. Dostosowuje learning rate dla każdego parametru na podstawie pierwszego i drugiego momentu gradientów.
- Można również użyć innych optymalizatorów, takich jak `optim.SGD` (Stochastic Gradient Descent) lub `optim.RMSprop`, zależnie od konkretnych wymagań zadania treningowego.
- Metoda `model.train()` ustawia model w trybie treningowym, dzięki czemu warstwy takie jak dropout i batch normalization zachowują się inaczej podczas treningu niż podczas ewaluacji.
- `optimizer.zero_grad()` usuwa gradienty wszystkich optymalizowanych tensorów przed przejściem wstecznym, co jest konieczne, ponieważ w PyTorch gradienty są domyślnie kumulowane. Jeśli nie zostaną usunięte, gradienty z poprzednich iteracji zostaną dodane do bieżących gradientów, prowadząc do nieprawidłowych aktualizacji.
- `loss.backward()` oblicza gradienty straty względem parametrów modelu, które następnie są używane przez optymalizator do aktualizacji wag.
- `optimizer.step()` aktualizuje parametry modelu na podstawie obliczonych gradientów i learning rate.
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
## Rekurencyjne sieci neuronowe (RNN) <sup>[[3]](#references)</sup>

Rekurencyjne sieci neuronowe (RNN) to klasa sieci neuronowych zaprojektowanych do przetwarzania danych sekwencyjnych, takich jak szeregi czasowe lub język naturalny. W przeciwieństwie do tradycyjnych feedforward neural networks, RNN mają połączenia, które tworzą pętle zwrotne, dzięki czemu mogą utrzymywać hidden state przechowujący informacje o wcześniejszych danych wejściowych w sekwencji.

Główne komponenty RNN obejmują:
- **Warstwy rekurencyjne**: Warstwy te przetwarzają sekwencje wejściowe krok po kroku, aktualizując swój hidden state na podstawie bieżącego wejścia i poprzedniego hidden state. Dzięki temu RNN mogą uczyć się zależności czasowych w danych.
- **Hidden state**: Hidden state to wektor podsumowujący informacje z poprzednich kroków czasowych. Jest aktualizowany przy każdym kroku czasowym i używany do tworzenia predykcji dla bieżącego wejścia.
- **Warstwa wyjściowa**: Warstwa wyjściowa generuje końcowe predykcje na podstawie hidden state. W wielu przypadkach RNN są używane do zadań takich jak modelowanie języka, gdzie wyjściem jest rozkład prawdopodobieństwa dla następnego słowa w sekwencji.

Na przykład w modelu językowym RNN przetwarza sekwencję słów, na przykład „The cat sat on the”, i przewiduje następne słowo na podstawie kontekstu dostarczonego przez poprzednie słowa, w tym przypadku „mat”.

### Long Short-Term Memory (LSTM) i Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

RNN są szczególnie skuteczne w zadaniach obejmujących dane sekwencyjne, takich jak modelowanie języka, machine translation i speech recognition. Mogą jednak mieć trudności z **zależnościami dalekiego zasięgu z powodu problemów takich jak zanikające gradienty**.

Aby rozwiązać ten problem, opracowano wyspecjalizowane architektury, takie jak Long Short-Term Memory (LSTM) i Gated Recurrent Unit (GRU). Architektury te wprowadzają mechanizmy bramkujące, które kontrolują przepływ informacji, umożliwiając skuteczniejsze wychwytywanie zależności dalekiego zasięgu.

- **LSTM**: Sieci LSTM używają trzech bramek (bramki wejściowej, bramki zapominania i bramki wyjściowej) do regulowania przepływu informacji do stanu komórki i z niego, dzięki czemu mogą zapamiętywać lub zapominać informacje w długich sekwencjach. Bramka wejściowa kontroluje, ile nowych informacji należy dodać na podstawie wejścia i poprzedniego hidden state, a bramka zapominania kontroluje, ile informacji odrzucić. Łącząc bramkę wejściową i bramkę zapominania, otrzymujemy nowy stan. Następnie, łącząc nowy stan komórki z wejściem i poprzednim hidden state, otrzymujemy również nowy hidden state.
- **GRU**: Sieci GRU upraszczają architekturę LSTM, łącząc bramki wejściową i zapominania w jedną bramkę aktualizacji, dzięki czemu są bardziej efektywne obliczeniowo, a jednocześnie nadal wychwytują zależności dalekiego zasięgu.

## LLM (Large Language Models)

Large Language Models (LLM) to rodzaj modeli deep learningu zaprojektowanych specjalnie do zadań związanych z przetwarzaniem języka naturalnego. Są trenowane na ogromnych ilościach danych tekstowych i mogą generować tekst przypominający tekst tworzony przez człowieka, odpowiadać na pytania, tłumaczyć języki oraz wykonywać różne inne zadania związane z językiem.
LLM są zwykle oparte na architekturach transformer, które wykorzystują mechanizmy self-attention do wychwytywania relacji między słowami w sekwencji, co pozwala im rozumieć kontekst i generować spójny tekst.

### Architektura transformera <sup>[[4]](#references)</sup>
Architektura transformera stanowi podstawę wielu LLM. Składa się ze struktury encoder-decoder, w której encoder przetwarza sekwencję wejściową, a decoder generuje sekwencję wyjściową. Główne komponenty architektury transformera obejmują:
- **Mechanizm self-attention**: Mechanizm ten pozwala modelowi oceniać znaczenie różnych słów w sekwencji podczas generowania reprezentacji. Oblicza on scores uwagi na podstawie relacji między słowami, umożliwiając modelowi skupienie się na istotnym kontekście.
- **Multi-Head Attention**: Komponent ten pozwala modelowi wychwytywać wiele relacji między słowami za pomocą wielu głów uwagi, z których każda skupia się na innych aspektach wejścia.
- **Kodowanie pozycyjne**: Ponieważ transformery nie mają wbudowanego pojęcia kolejności słów, do embeddings wejściowych dodaje się kodowanie pozycyjne, aby dostarczyć informacji o pozycji słów w sekwencji.

## Modele dyfuzyjne <sup>[[5]](#references)</sup>
Modele dyfuzyjne to klasa modeli generatywnych, które uczą się generować dane poprzez symulowanie procesu dyfuzji. Są szczególnie skuteczne w zadaniach takich jak generowanie obrazów i zyskały popularność w ostatnich latach.
Modele dyfuzyjne działają poprzez stopniowe przekształcanie prostego rozkładu szumu w złożony rozkład danych za pomocą serii kroków dyfuzji. Główne komponenty modeli dyfuzyjnych obejmują:
- **Proces dyfuzji w przód**: Proces ten stopniowo dodaje szum do danych, przekształcając je w prosty rozkład szumu. Proces dyfuzji w przód jest zwykle definiowany za pomocą serii poziomów szumu, gdzie każdy poziom odpowiada określonej ilości szumu dodanego do danych.
- **Proces dyfuzji wstecznej**: Proces ten uczy się odwracać proces dyfuzji w przód, stopniowo odszumiając dane w celu generowania próbek z docelowego rozkładu. Proces dyfuzji wstecznej jest trenowany za pomocą funkcji straty, która zachęca model do odtworzenia oryginalnych danych z zaszumionych próbek.

Ponadto, aby wygenerować obraz na podstawie promptu tekstowego, modele dyfuzyjne zwykle wykonują następujące kroki:
1. **Kodowanie tekstu**: Prompt tekstowy jest kodowany do reprezentacji latentnej za pomocą encodera tekstu (np. modelu opartego na transformerze). Reprezentacja ta odwzorowuje znaczenie semantyczne tekstu.
2. **Próbkowanie szumu**: Losowy wektor szumu jest próbkowany z rozkładu Gaussa.
3. **Kroki dyfuzji**: Model stosuje serię kroków dyfuzji, stopniowo przekształcając wektor szumu w obraz odpowiadający promptowi tekstowemu. Każdy krok obejmuje zastosowanie wyuczonych transformacji w celu odszumienia obrazu.

## References

- [1] [PyTorch - samouczek dotyczący sieci neuronowych](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Od-Noise'owane probabilistyczne modele dyfuzyjne](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
