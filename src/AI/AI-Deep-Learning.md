# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning

Uczenie głębokie to podzbiór uczenia maszynowego, który wykorzystuje sieci neuronowe z wieloma warstwami (głębokie sieci neuronowe) do modelowania złożonych wzorców w danych. Osiągnęło ono niezwykły sukces w różnych dziedzinach, w tym w wizji komputerowej, przetwarzaniu języka naturalnego i rozpoznawaniu mowy.

### Neural Networks

Sieci neuronowe są podstawowymi elementami uczenia głębokiego. Składają się z połączonych węzłów (neuronów) zorganizowanych w warstwy. Każdy neuron otrzymuje dane wejściowe, stosuje ważoną sumę i przekazuje wynik przez funkcję aktywacji, aby uzyskać wyjście. Warstwy można sklasyfikować w następujący sposób:
- **Input Layer**: Pierwsza warstwa, która otrzymuje dane wejściowe.
- **Hidden Layers**: Warstwy pośrednie, które wykonują transformacje na danych wejściowych. Liczba warstw ukrytych i neuronów w każdej warstwie może się różnić, co prowadzi do różnych architektur.
- **Output Layer**: Ostatnia warstwa, która produkuje wyjście sieci, takie jak prawdopodobieństwa klas w zadaniach klasyfikacyjnych.

### Activation Functions

Gdy warstwa neuronów przetwarza dane wejściowe, każdy neuron stosuje wagę i bias do wejścia (`z = w * x + b`), gdzie `w` to waga, `x` to wejście, a `b` to bias. Wyjście neuronu jest następnie przekazywane przez **funkcję aktywacji, aby wprowadzić nieliniowość** do modelu. Ta funkcja aktywacji zasadniczo wskazuje, czy następny neuron "powinien być aktywowany i w jakim stopniu". Umożliwia to sieci uczenie się złożonych wzorców i relacji w danych, co pozwala jej przybliżać dowolną funkcję ciągłą.

Dlatego funkcje aktywacji wprowadzają nieliniowość do sieci neuronowej, umożliwiając jej uczenie się złożonych relacji w danych. Powszechne funkcje aktywacji to:
- **Sigmoid**: Mapuje wartości wejściowe na zakres między 0 a 1, często używane w klasyfikacji binarnej.
- **ReLU (Rectified Linear Unit)**: Zwraca bezpośrednio wejście, jeśli jest dodatnie; w przeciwnym razie zwraca zero. Jest szeroko stosowane ze względu na swoją prostotę i skuteczność w trenowaniu głębokich sieci.
- **Tanh**: Mapuje wartości wejściowe na zakres między -1 a 1, często używane w warstwach ukrytych.
- **Softmax**: Przekształca surowe wyniki w prawdopodobieństwa, często używane w warstwie wyjściowej do klasyfikacji wieloklasowej.

### Backpropagation

Backpropagation to algorytm używany do trenowania sieci neuronowych poprzez dostosowywanie wag połączeń między neuronami. Działa poprzez obliczanie gradientu funkcji straty względem każdej wagi i aktualizowanie wag w przeciwnym kierunku gradientu, aby zminimalizować stratę. Kroki zaangażowane w backpropagation to:

1. **Forward Pass**: Oblicz wyjście sieci, przekazując dane wejściowe przez warstwy i stosując funkcje aktywacji.
2. **Loss Calculation**: Oblicz stratę (błąd) między przewidywanym wyjściem a prawdziwym celem za pomocą funkcji straty (np. średni błąd kwadratowy dla regresji, entropia krzyżowa dla klasyfikacji).
3. **Backward Pass**: Oblicz gradienty straty względem każdej wagi, korzystając z reguły łańcuchowej rachunku różniczkowego.
4. **Weight Update**: Zaktualizuj wagi, korzystając z algorytmu optymalizacji (np. stochastyczny spadek gradientu, Adam), aby zminimalizować stratę.

## Convolutional Neural Networks (CNNs)

Konwolucyjne sieci neuronowe (CNN) to specjalizowany typ sieci neuronowej zaprojektowany do przetwarzania danych w formie siatki, takich jak obrazy. Są szczególnie skuteczne w zadaniach związanych z wizją komputerową dzięki swojej zdolności do automatycznego uczenia się przestrzennych hierarchii cech.

Główne komponenty CNN to:
- **Convolutional Layers**: Stosują operacje konwolucji do danych wejściowych, używając uczących się filtrów (jąder) do wydobywania lokalnych cech. Każdy filtr przesuwa się po wejściu i oblicza iloczyn skalarny, produkując mapę cech.
- **Pooling Layers**: Zmniejszają rozmiary map cech, zachowując ważne cechy. Powszechne operacje poolingowe to max pooling i average pooling.
- **Fully Connected Layers**: Łączą każdy neuron w jednej warstwie z każdym neuronem w następnej warstwie, podobnie jak w tradycyjnych sieciach neuronowych. Te warstwy są zazwyczaj używane na końcu sieci do zadań klasyfikacyjnych.

Wewnątrz CNN **`Convolutional Layers`**, możemy również wyróżnić:
- **Initial Convolutional Layer**: Pierwsza warstwa konwolucyjna, która przetwarza surowe dane wejściowe (np. obraz) i jest przydatna do identyfikacji podstawowych cech, takich jak krawędzie i tekstury.
- **Intermediate Convolutional Layers**: Kolejne warstwy konwolucyjne, które budują na cechach wyuczonych przez warstwę początkową, pozwalając sieci na uczenie się bardziej złożonych wzorców i reprezentacji.
- **Final Convolutional Layer**: Ostatnie warstwy konwolucyjne przed warstwami w pełni połączonymi, które uchwycają cechy na wysokim poziomie i przygotowują dane do klasyfikacji.

> [!TIP]
> CNN są szczególnie skuteczne w klasyfikacji obrazów, detekcji obiektów i zadaniach segmentacji obrazów dzięki ich zdolności do uczenia się przestrzennych hierarchii cech w danych w formie siatki oraz redukcji liczby parametrów poprzez dzielenie wag.
> Co więcej, działają lepiej z danymi wspierającymi zasadę lokalności cech, gdzie sąsiednie dane (piksele) są bardziej prawdopodobne, że są ze sobą powiązane niż odległe piksele, co może nie mieć miejsca w przypadku innych typów danych, takich jak tekst.
> Ponadto, zauważ, jak CNN będą w stanie identyfikować nawet złożone cechy, ale nie będą w stanie zastosować żadnego kontekstu przestrzennego, co oznacza, że ta sama cecha znaleziona w różnych częściach obrazu będzie taka sama.

### Example defining a CNN

*Tutaj znajdziesz opis, jak zdefiniować konwolucyjną sieć neuronową (CNN) w PyTorch, która zaczyna się od partii obrazów RGB jako zbioru danych o rozmiarze 48x48 i wykorzystuje warstwy konwolucyjne oraz maxpool do wydobywania cech, a następnie warstwy w pełni połączone do klasyfikacji.*

Tak można zdefiniować 1 warstwę konwolucyjną w PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Liczba kanałów wejściowych. W przypadku obrazów RGB jest to 3 (jeden dla każdego kanału kolorystycznego). Jeśli pracujesz z obrazami w odcieniach szarości, będzie to 1.

- `out_channels`: Liczba kanałów wyjściowych (filtrów), które warstwa konwolucyjna będzie uczyć. To jest hiperparametr, który możesz dostosować w zależności od architektury swojego modelu.

- `kernel_size`: Rozmiar filtra konwolucyjnego. Powszechnym wyborem jest 3x3, co oznacza, że filtr pokryje obszar 3x3 obrazu wejściowego. To jak stempel kolorowy 3×3×3, który jest używany do generowania out_channels z in_channels:
1. Umieść ten stempel 3×3×3 w lewym górnym rogu sześcianu obrazu.
2. Pomnóż każdą wagę przez piksel pod nim, dodaj je wszystkie, dodaj bias → otrzymujesz jedną liczbę.
3. Zapisz tę liczbę na pustej mapie w pozycji (0, 0).
4. Przesuń stempel o jeden piksel w prawo (stride = 1) i powtórz, aż wypełnisz całą siatkę 48×48.

- `padding`: Liczba pikseli dodawanych do każdej strony wejścia. Padding pomaga zachować wymiary przestrzenne wejścia, co pozwala na większą kontrolę nad rozmiarem wyjścia. Na przykład, przy jądrze 3x3 i wejściu o rozmiarze 48x48, padding równy 1 zachowa ten sam rozmiar wyjścia (48x48) po operacji konwolucji. Dzieje się tak, ponieważ padding dodaje obramowanie o 1 pikselu wokół obrazu wejściowego, co pozwala jądrowi przesuwać się po krawędziach bez zmniejszania wymiarów przestrzennych.

Wówczas liczba parametrów do wytrenowania w tej warstwie wynosi:
- (3x3x3 (rozmiar jądra) + 1 (bias)) x 32 (out_channels) = 896 parametrów do wytrenowania.

Zauważ, że do każdego używanego jądra dodawany jest bias (+1), ponieważ funkcją każdej warstwy konwolucyjnej jest nauczenie się liniowej transformacji wejścia, co jest reprezentowane przez równanie:
```plaintext
Y = f(W * X + b)
```
gdzie `W` to macierz wag (nauczone filtry, 3x3x3 = 27 parametrów), `b` to wektor biasu, który wynosi +1 dla każdego kanału wyjściowego.

Zauważ, że wyjście `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` będzie tensor o kształcie `(batch_size, 32, 48, 48)`, ponieważ 32 to nowa liczba generowanych kanałów o rozmiarze 48x48 pikseli.

Następnie możemy połączyć tę warstwę konwolucyjną z inną warstwą konwolucyjną, jak: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Co doda: (32x3x3 (rozmiar jądra) + 1 (bias)) x 64 (out_channels) = 18,496 parametrów do wytrenowania i wyjście o kształcie `(batch_size, 64, 48, 48)`.

Jak widać, **liczba parametrów szybko rośnie z każdą dodatkową warstwą konwolucyjną**, szczególnie w miarę zwiększania liczby kanałów wyjściowych.

Jedną z opcji kontrolowania ilości używanych danych jest zastosowanie **max pooling** po każdej warstwie konwolucyjnej. Max pooling redukuje wymiary przestrzenne map cech, co pomaga zmniejszyć liczbę parametrów i złożoność obliczeniową, jednocześnie zachowując ważne cechy.

Można to zadeklarować jako: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. To zasadniczo wskazuje na użycie siatki 2x2 pikseli i pobranie maksymalnej wartości z każdej siatki, aby zmniejszyć rozmiar mapy cech o połowę. Ponadto `stride=2` oznacza, że operacja poolingowa będzie przesuwać się o 2 piksele na raz, w tym przypadku zapobiegając jakimkolwiek nakładkom między obszarami poolingowymi.

Z tą warstwą poolingową, kształt wyjścia po pierwszej warstwie konwolucyjnej wynosiłby `(batch_size, 64, 24, 24)` po zastosowaniu `self.pool1` do wyjścia `self.conv2`, zmniejszając rozmiar do 1/4 poprzedniej warstwy.

> [!TIP]
> Ważne jest, aby stosować pooling po warstwach konwolucyjnych, aby zmniejszyć wymiary przestrzenne map cech, co pomaga kontrolować liczbę parametrów i złożoność obliczeniową, jednocześnie sprawiając, że początkowy parametr uczy się ważnych cech.
> Możesz postrzegać konwolucje przed warstwą poolingową jako sposób na wydobycie cech z danych wejściowych (jak linie, krawędzie), ta informacja nadal będzie obecna w wyjściu po pooling, ale następna warstwa konwolucyjna nie będzie mogła zobaczyć oryginalnych danych wejściowych, tylko wyjście po pooling, które jest zredukowaną wersją poprzedniej warstwy z tą informacją.
> W zwykłej kolejności: `Conv → ReLU → Pool` każde okno poolingowe 2×2 teraz konkurowało z aktywacjami cech (“krawędź obecna / nie”), a nie surowymi intensywnościami pikseli. Utrzymanie najsilniejszej aktywacji naprawdę zachowuje najbardziej istotne dowody.

Następnie, po dodaniu tylu warstw konwolucyjnych i poolingowych, ile to konieczne, możemy spłaszczyć wyjście, aby wprowadzić je do w pełni połączonych warstw. Robi się to przez przekształcenie tensora w wektor 1D dla każdej próbki w partii:
```python
x = x.view(-1, 64*24*24)
```
A z tym wektorem 1D zawierającym wszystkie parametry treningowe wygenerowane przez poprzednie warstwy konwolucyjne i poolingowe, możemy zdefiniować warstwę w pełni połączoną w następujący sposób:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Który weźmie spłaszczone wyjście z poprzedniej warstwy i odwzoruje je na 512 ukrytych jednostek.

Zauważ, że ta warstwa dodała `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` trenowalnych parametrów, co stanowi znaczący wzrost w porównaniu do warstw konwolucyjnych. Dzieje się tak, ponieważ warstwy w pełni połączone łączą każdy neuron w jednej warstwie z każdym neuronem w następnej warstwie, co prowadzi do dużej liczby parametrów.

Na koniec możemy dodać warstwę wyjściową, aby wygenerować ostateczne logity klas:
```python
self.fc2 = nn.Linear(512, num_classes)
```
To doda `(512 + 1 (bias)) * num_classes` parametry do uczenia, gdzie `num_classes` to liczba klas w zadaniu klasyfikacji (np. 43 dla zestawu danych GTSRB).

Jedną z ostatnich powszechnych praktyk jest dodanie warstwy dropout przed w pełni połączonymi warstwami, aby zapobiec przeuczeniu. Można to zrobić za pomocą:
```python
self.dropout = nn.Dropout(0.5)
```
Ta warstwa losowo ustawia ułamek jednostek wejściowych na zero podczas treningu, co pomaga zapobiegać przeuczeniu, zmniejszając zależność od konkretnych neuronów.

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
### Przykład kodu treningowego CNN

Poniższy kod stworzy dane treningowe i wytrenuje model `MY_NET` zdefiniowany powyżej. Oto kilka interesujących wartości do zauważenia:

- `EPOCHS` to liczba razy, kiedy model zobaczy cały zbiór danych podczas treningu. Jeśli EPOCH jest zbyt mały, model może nie nauczyć się wystarczająco; jeśli zbyt duży, może przeuczyć się.
- `LEARNING_RATE` to rozmiar kroku dla optymalizatora. Mała wartość learning rate może prowadzić do wolnej konwergencji, podczas gdy duża może przekroczyć optymalne rozwiązanie i uniemożliwić konwergencję.
- `WEIGHT_DECAY` to termin regularizacji, który pomaga zapobiegać przeuczeniu poprzez karanie dużych wag.

Jeśli chodzi o pętlę treningową, oto kilka interesujących informacji do poznania:
- `criterion = nn.CrossEntropyLoss()` to funkcja straty używana do zadań klasyfikacji wieloklasowej. Łączy aktywację softmax i stratę krzyżową w jednej funkcji, co czyni ją odpowiednią do trenowania modeli, które zwracają logity klas.
- Jeśli model miałby zwracać inne typy wyjść, takie jak klasyfikacja binarna lub regresja, używalibyśmy różnych funkcji straty, takich jak `nn.BCEWithLogitsLoss()` dla klasyfikacji binarnej lub `nn.MSELoss()` dla regresji.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` inicjalizuje optymalizator Adam, który jest popularnym wyborem do trenowania modeli głębokiego uczenia. Dostosowuje on learning rate dla każdego parametru na podstawie pierwszych i drugich momentów gradientów.
- Inne optymalizatory, takie jak `optim.SGD` (Stochastic Gradient Descent) lub `optim.RMSprop`, mogą być również używane, w zależności od specyficznych wymagań zadania treningowego.
- Metoda `model.train()` ustawia model w tryb treningowy, umożliwiając warstwom takim jak dropout i normalizacja wsadowa zachowanie się inaczej podczas treningu w porównaniu do ewaluacji.
- `optimizer.zero_grad()` czyści gradienty wszystkich optymalizowanych tensorów przed przejściem wstecznym, co jest konieczne, ponieważ gradienty domyślnie kumulują się w PyTorch. Jeśli nie zostaną wyczyszczone, gradienty z poprzednich iteracji byłyby dodawane do bieżących gradientów, co prowadziłoby do niepoprawnych aktualizacji.
- `loss.backward()` oblicza gradienty straty względem parametrów modelu, które są następnie używane przez optymalizator do aktualizacji wag.
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
## Sieci Neuronowe Rekurencyjne (RNN)

Sieci Neuronowe Rekurencyjne (RNN) to klasa sieci neuronowych zaprojektowanych do przetwarzania danych sekwencyjnych, takich jak szereg czasowy lub język naturalny. W przeciwieństwie do tradycyjnych sieci neuronowych typu feedforward, RNN mają połączenia, które wracają do siebie, co pozwala im utrzymywać ukryty stan, który przechwycuje informacje o poprzednich wejściach w sekwencji.

Główne składniki RNN obejmują:
- **Warstwy Rekurencyjne**: Te warstwy przetwarzają sekwencje wejściowe krok po kroku, aktualizując swój ukryty stan na podstawie bieżącego wejścia i poprzedniego ukrytego stanu. To pozwala RNN uczyć się zależności czasowych w danych.
- **Ukryty Stan**: Ukryty stan to wektor, który podsumowuje informacje z poprzednich kroków czasowych. Jest aktualizowany w każdym kroku czasowym i jest używany do dokonywania prognoz dla bieżącego wejścia.
- **Warstwa Wyjściowa**: Warstwa wyjściowa produkuje ostateczne prognozy na podstawie ukrytego stanu. W wielu przypadkach RNN są używane do zadań takich jak modelowanie języka, gdzie wyjście jest rozkładem prawdopodobieństwa dla następnego słowa w sekwencji.

Na przykład, w modelu językowym, RNN przetwarza sekwencję słów, na przykład "Kot usiadł na" i przewiduje następne słowo na podstawie kontekstu dostarczonego przez poprzednie słowa, w tym przypadku "macie".

### Długoterminowa Pamięć Krótkoterminowa (LSTM) i Gated Recurrent Unit (GRU)

RNN są szczególnie skuteczne w zadaniach związanych z danymi sekwencyjnymi, takimi jak modelowanie języka, tłumaczenie maszynowe i rozpoznawanie mowy. Jednak mogą mieć trudności z **długozasięgowymi zależnościami z powodu problemów takich jak znikające gradienty**.

Aby to rozwiązać, opracowano specjalistyczne architektury, takie jak Długoterminowa Pamięć Krótkoterminowa (LSTM) i Gated Recurrent Unit (GRU). Te architektury wprowadzają mechanizmy bramkowe, które kontrolują przepływ informacji, co pozwala im skuteczniej uchwycić długozasięgowe zależności.

- **LSTM**: Sieci LSTM używają trzech bramek (bramka wejściowa, bramka zapomnienia i bramka wyjściowa) do regulacji przepływu informacji do i z stanu komórki, co umożliwia im zapamiętywanie lub zapominanie informacji w długich sekwencjach. Bramka wejściowa kontroluje, ile nowych informacji dodać na podstawie wejścia i poprzedniego ukrytego stanu, bramka zapomnienia kontroluje, ile informacji odrzucić. Łącząc bramkę wejściową i bramkę zapomnienia, uzyskujemy nowy stan. Na koniec, łącząc nowy stan komórki z wejściem i poprzednim ukrytym stanem, uzyskujemy również nowy ukryty stan.
- **GRU**: Sieci GRU upraszczają architekturę LSTM, łącząc bramki wejściowe i zapomnienia w jedną bramkę aktualizacji, co czyni je obliczeniowo bardziej wydajnymi, jednocześnie uchwytując długozasięgowe zależności.

## LLMs (Duże Modele Językowe)

Duże Modele Językowe (LLMs) to rodzaj modelu głębokiego uczenia, zaprojektowanego specjalnie do zadań przetwarzania języka naturalnego. Są trenowane na ogromnych ilościach danych tekstowych i mogą generować tekst przypominający ludzki, odpowiadać na pytania, tłumaczyć języki i wykonywać różne inne zadania związane z językiem.
LLMs są zazwyczaj oparte na architekturach transformatorowych, które wykorzystują mechanizmy samouważności do uchwycenia relacji między słowami w sekwencji, co pozwala im zrozumieć kontekst i generować spójny tekst.

### Architektura Transformatora
Architektura transformatora jest podstawą wielu LLMs. Składa się z struktury kodera-dekodera, gdzie koder przetwarza sekwencję wejściową, a dekoder generuje sekwencję wyjściową. Kluczowe składniki architektury transformatora obejmują:
- **Mechanizm Samouważności**: Ten mechanizm pozwala modelowi ocenić znaczenie różnych słów w sekwencji podczas generowania reprezentacji. Oblicza wyniki uwagi na podstawie relacji między słowami, co umożliwia modelowi skupienie się na odpowiednim kontekście.
- **Uwaga Wielogłowa**: Ten komponent pozwala modelowi uchwycić wiele relacji między słowami, używając wielu głów uwagi, z których każda koncentruje się na różnych aspektach wejścia.
- **Kodowanie Pozycyjne**: Ponieważ transformatory nie mają wbudowanego pojęcia kolejności słów, kodowanie pozycyjne jest dodawane do osadzeń wejściowych, aby dostarczyć informacji o pozycji słów w sekwencji.

## Modele Dyfuzji
Modele dyfuzji to klasa modeli generatywnych, które uczą się generować dane, symulując proces dyfuzji. Są szczególnie skuteczne w zadaniach takich jak generowanie obrazów i zyskały popularność w ostatnich latach.
Modele dyfuzji działają poprzez stopniowe przekształcanie prostej rozkładu szumów w złożony rozkład danych poprzez szereg kroków dyfuzji. Kluczowe składniki modeli dyfuzji obejmują:
- **Proces Dyfuzji Naprzód**: Ten proces stopniowo dodaje szum do danych, przekształcając je w prosty rozkład szumów. Proces dyfuzji naprzód jest zazwyczaj definiowany przez szereg poziomów szumów, gdzie każdy poziom odpowiada określonej ilości szumu dodanego do danych.
- **Proces Dyfuzji Wstecz**: Ten proces uczy się odwracać proces dyfuzji naprzód, stopniowo usuwając szum z danych, aby generować próbki z docelowego rozkładu. Proces dyfuzji wstecz jest trenowany przy użyciu funkcji straty, która zachęca model do rekonstrukcji oryginalnych danych z zaszumionych próbek.

Ponadto, aby wygenerować obraz z tekstowego podpowiedzi, modele dyfuzji zazwyczaj wykonują następujące kroki:
1. **Kodowanie Tekstu**: Tekstowa podpowiedź jest kodowana w latentną reprezentację za pomocą kodera tekstu (np. modelu opartego na transformatorze). Ta reprezentacja uchwyca semantyczne znaczenie tekstu.
2. **Próbkowanie Szumu**: Losowy wektor szumu jest próbkowany z rozkładu Gaussa.
3. **Kroki Dyfuzji**: Model stosuje szereg kroków dyfuzji, stopniowo przekształcając wektor szumu w obraz, który odpowiada tekstowej podpowiedzi. Każdy krok polega na zastosowaniu wyuczonych transformacji w celu usunięcia szumu z obrazu.

{{#include ../banners/hacktricks-training.md}}
