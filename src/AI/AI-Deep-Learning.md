# 深層学習

{{#include ../banners/hacktricks-training.md}}

## 深層学習 <sup>[[1]](#references)</sup>

深層学習は、データ内の複雑なパターンをモデル化するために、複数の層を持つニューラルネットワーク（deep neural networks）を使用する機械学習の一分野です。コンピュータビジョン、自然言語処理、音声認識など、さまざまな分野で目覚ましい成果を上げています。

### ニューラルネットワーク

ニューラルネットワークは深層学習の構成要素です。ニューラルネットワークは、層状に構成された相互接続ノード（ニューロン）で構成されます。各ニューロンは入力を受け取り、重み付き和を計算し、その結果を activation function に渡して出力を生成します。層は次のように分類できます。
- **Input Layer**: 入力データを受け取る最初の層。
- **Hidden Layers**: 入力データに変換処理を行う中間層。隠れ層の数や各層のニューロン数は変更できるため、さまざまなアーキテクチャが存在します。
- **Output Layer**: 分類タスクにおけるクラス確率など、ネットワークの出力を生成する最後の層。


### Activation Functions

ニューロンの層が入力データを処理するとき、各ニューロンは入力に重みとバイアスを適用します（`z = w * x + b`）。ここで、`w` は重み、`x` は入力、`b` はバイアスです。その後、ニューロンの出力は、モデルに**非線形性を導入するための activation function**を通過します。この activation function は基本的に、次のニューロンが「活性化されるべきか、またどの程度活性化されるべきか」を示します。これにより、ネットワークはデータ内の複雑なパターンや関係を学習でき、任意の連続関数を近似できるようになります。

したがって、activation functions はニューラルネットワークに非線形性を導入し、データ内の複雑な関係を学習できるようにします。一般的な activation functions には次のものがあります。
- **Sigmoid**: 入力値を 0 から 1 の範囲に変換します。二値分類でよく使用されます。
- **ReLU (Rectified Linear Unit)**: 入力が正の場合は入力をそのまま出力し、それ以外の場合は 0 を出力します。単純かつ深いネットワークのトレーニングに効果的であるため、広く使用されています。
- **Tanh**: 入力値を -1 から 1 の範囲に変換します。隠れ層でよく使用されます。
- **Softmax**: 生のスコアを確率に変換します。多クラス分類の出力層でよく使用されます。

### Backpropagation

Backpropagation は、ニューロン間の接続の重みを調整してニューラルネットワークをトレーニングするために使用されるアルゴリズムです。損失関数に対する各重みの勾配を計算し、損失を最小化するために勾配とは反対方向へ重みを更新します。Backpropagation の手順は次のとおりです。

1. **Forward Pass**: 入力を各層に通し、activation functions を適用してネットワークの出力を計算します。
2. **Loss Calculation**: loss function を使用して、予測された出力と正しい target の間の損失（誤差）を計算します（回帰では平均二乗誤差、分類では cross-entropy など）。
3. **Backward Pass**: 微分積分の連鎖律を使用して、各重みに対する損失の勾配を計算します。
4. **Weight Update**: optimization algorithm（stochastic gradient descent や Adam など）を使用して重みを更新し、損失を最小化します。

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Convolutional Neural Networks (CNNs) は、画像などのグリッド状データを処理するために設計された特殊なニューラルネットワークです。特徴の空間的階層を自動的に学習できるため、コンピュータビジョンタスクに特に効果的です。

CNNs の主な構成要素は次のとおりです。
- **Convolutional Layers**: 学習可能な filters（kernels）を使用して入力データに convolution operations を適用し、局所的な特徴を抽出します。各 filter は入力上をスライドし、dot product を計算して feature map を生成します。
- **Pooling Layers**: 重要な特徴を保持しながら feature maps を downsample し、空間的な次元を削減します。一般的な pooling operations には max pooling と average pooling があります。
- **Fully Connected Layers**: 従来のニューラルネットワークと同様に、ある層のすべてのニューロンを次の層のすべてのニューロンに接続します。通常、これらの層は分類タスクのためにネットワークの末尾で使用されます。

CNN の **`Convolutional Layers`** 内部は、さらに次のように分類できます。
- **Initial Convolutional Layer**: raw input data（画像など）を処理する最初の convolutional layer であり、エッジやテクスチャなどの基本的な特徴を識別するのに役立ちます。
- **Intermediate Convolutional Layers**: Initial Layer で学習した特徴を基に構築する後続の convolutional layers であり、ネットワークがより複雑なパターンや表現を学習できるようにします。
- **Final Convolutional Layer**: fully connected layers の前にある最後の convolutional layers であり、高レベルの特徴を捉え、データを分類に備えます。

> [!TIP]
> CNNs は、グリッド状データ内の特徴の空間的階層を学習し、weight sharing によってパラメータ数を削減できるため、画像分類、object detection、画像 segmentation タスクに特に効果的です。
> さらに、特徴局所性の原則をサポートするデータ、つまり遠く離れたピクセルよりも隣接するデータ（ピクセル）のほうが関連している可能性が高いデータに対して、より適切に機能します。これは、text など他の種類のデータには当てはまらない場合があります。
> また、CNNs は複雑な特徴さえ識別できますが、空間的なコンテキストを適用できない点にも注意してください。つまり、画像内の異なる場所で見つかった同じ特徴は、同じものとして扱われます。

### CNN を定義する例

*ここでは、48x48 サイズの RGB 画像の batch を dataset として受け取り、convolutional layers と maxpool を使用して特徴を抽出した後、classification のために fully connected layers を使用する、PyTorch で Convolutional Neural Network (CNN) を定義する方法を説明します。*

PyTorch で convolutional layer を 1 つ定義する方法は次のとおりです。`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`。

- `in_channels`: 入力チャンネル数。RGB 画像の場合は 3（各色チャンネルに 1 つ）です。grayscale images を扱う場合は 1 になります。

- `out_channels`: convolutional layer が学習する出力チャンネル（filters）の数です。これはモデルアーキテクチャに基づいて調整できる hyperparameter です。

- `kernel_size`: convolutional filter のサイズです。一般的には 3x3 が使用され、これは filter が入力画像の 3x3 の領域を覆うことを意味します。これは、in_channels から out_channels を生成するために使用される 3×3×3 の色付きスタンプのようなものです。
1. その 3×3×3 のスタンプを、画像 cube の左上隅に配置します。
2. すべての重みに、その直下にあるピクセルを掛け、すべてを加算し、bias を加えます → 1 つの数値が得られます。
3. その数値を、空の map の位置 (0, 0) に書き込みます。
4. スタンプを右に 1 ピクセル（stride = 1）スライドさせ、48×48 の grid 全体が埋まるまで繰り返します。

- `padding`: 入力の各辺に追加されるピクセル数です。Padding は入力の空間的な次元を維持するのに役立ち、出力サイズをより細かく制御できるようにします。たとえば、3x3 kernel と 48x48 ピクセルの入力に対して padding を 1 にすると、convolution operation 後も出力サイズは同じ（48x48）になります。これは、padding によって入力画像の周囲に 1 ピクセルの border が追加され、空間的な次元を縮小せずに kernel が端の上をスライドできるようになるためです。

したがって、この layer の trainable parameters 数は次のようになります。
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 trainable parameters.

各 convolutional layer の機能は、次の式で表される入力の線形変換を学習することなので、使用される各 kernel には Bias (+1) が 1 つ追加されることに注意してください。
```plaintext
Y = f(W * X + b)
```
ここで、`W` は重み行列（学習されたフィルター、3x3x3 = 27 params）、`b` は各 output channel に対して +1 となるバイアスベクトルです。

`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` の出力は、形状 `(batch_size, 32, 48, 48)` のテンソルになります。これは、32 がサイズ 48x48 pixels の新たに生成された channels の数だからです。

次に、この convolutional layer を以下のように別の convolutional layer に接続できます: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`。

これにより、(32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 個の trainable parameters と、形状 `(batch_size, 64, 48, 48)` の出力が追加されます。

ご覧のとおり、**追加する convolutional layer ごとにパラメータ数は急速に増加します**。特に、output channels の数が増えると顕著です。

使用するデータ量を制御する方法の1つは、各 convolutional layer の後に **max pooling** を使用することです。Max pooling は feature maps の空間次元を縮小します。これにより、重要な features を保持しながら、パラメータ数と計算の複雑さを削減できます。

これは次のように宣言できます: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`。これは基本的に、2x2 pixels の grid を使用し、各 grid から最大値を取得して feature map のサイズを半分にすることを示しています。さらに、`stride=2` は pooling operation が一度に 2 pixels ずつ移動することを意味します。この場合、pooling regions 間の重複を防ぎます。

この pooling layer を使用すると、最初の convolutional layer 後の出力形状は、`self.conv2` の出力に `self.pool1` を適用した後の `(batch_size, 64, 24, 24)` になります。これは、前の layer のサイズを 1/4 に縮小します。

> [!TIP]
> feature maps の空間次元を縮小し、パラメータ数と計算の複雑さを制御しながら、initial parameter が重要な features を学習できるようにするため、convolutional layers の後に pooling を行うことが重要です。
>Pooling layer の前にある convolutions は、入力データから features（lines、edges など）を抽出する方法と考えることができます。この情報は pooled output にも残りますが、次の convolutional layer は元の入力データを見ることができず、前の layer を縮小したバージョンである pooled output のみを見ることになります。そこには、その情報が含まれています。
>通常の順序である `Conv → ReLU → Pool` では、各 2×2 pooling window は raw pixel intensities ではなく、feature activations（「edge present / not」）を扱います。最も強い activation を保持することで、最も salient な evidence を実際に保持できます。

その後、必要な数の convolutional layers と pooling layers を追加したら、output を flatten して fully connected layers に入力できます。これは、batch 内の各 sample について tensor を1D vector に reshape することで行います:
```python
x = x.view(-1, 64*24*24)
```
そして、前の畳み込み層とプーリング層によって生成されたすべての学習パラメータを含むこの1Dベクトルを使って、次のように全結合層を定義できます:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
前のレイヤーのflattenされた出力を受け取り、512個のhidden unitsにマッピングします。

このレイヤーでは、`(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504`個のtrainable parametersが追加されていることに注目してください。これはconvolutional layersと比較して大幅な増加です。fully connected layersでは、あるレイヤーのすべてのニューロンを次のレイヤーのすべてのニューロンに接続するため、多数のparametersが必要になります。

最後に、最終的なclass logitsを生成するためのoutput layerを追加できます：
```python
self.fc2 = nn.Linear(512, num_classes)
```
これにより、`num_classes`（分類タスクにおけるクラス数。例：GTSRBデータセットでは43）個のクラスに対して、`(512 + 1 (bias)) * num_classes` 個のtrainable parametersが追加されます。

もう一つの一般的なpracticeとして、overfittingを防ぐためにfully connected layersの前にdropout layerを追加します。これは次のように実行できます：
```python
self.dropout = nn.Dropout(0.5)
```
この層は、トレーニング中に入力ユニットの一部をランダムにゼロに設定します。これにより、特定のニューロンへの依存を減らし、過学習を防ぎます。

### CNN コード例
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

以下のコードは、トレーニングデータを作成し、上で定義した `MY_NET` モデルをトレーニングします。注目すべき値は次のとおりです。

- `EPOCHS` は、トレーニング中にモデルがデータセット全体を見る回数です。EPOCH が小さすぎると、モデルが十分に学習できない場合があります。大きすぎると、過学習する可能性があります。
- `LEARNING_RATE` は、optimizer のステップサイズです。learning rate が小さいと収束が遅くなる可能性があり、大きいと最適解を飛び越えて収束できなくなる可能性があります。
- `WEIGHT_DECAY` は、大きな重みにペナルティを課すことで過学習を防ぐための正則化項です。

トレーニングループについて、知っておくべき興味深い情報は次のとおりです。
- `criterion = nn.CrossEntropyLoss()` は、多クラス分類タスクで使用される損失関数です。softmax activation と cross-entropy loss を単一の関数に組み合わせているため、class logits を出力するモデルのトレーニングに適しています。
- モデルが binary classification や regression など、別の種類の出力を行うことが想定される場合は、binary classification には `nn.BCEWithLogitsLoss()`、regression には `nn.MSELoss()` など、異なる損失関数を使用します。
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` は、deep learning モデルのトレーニングで広く使われる Adam optimizer を初期化します。gradient の1次モーメントと2次モーメントに基づいて、各パラメータの learning rate を調整します。
- `optim.SGD` (Stochastic Gradient Descent) や `optim.RMSprop` などの他の optimizer も、トレーニングタスクの具体的な要件に応じて使用できます。
- `model.train()` メソッドはモデルをトレーニングモードに設定し、dropout や batch normalization などのレイヤーが evaluation 時とは異なる動作をするようにします。
- `optimizer.zero_grad()` は backward pass の前に、最適化対象となるすべての tensor の gradient を消去します。PyTorch ではデフォルトで gradient が蓄積されるため、これは必要な処理です。消去しない場合、前の iteration の gradient が現在の gradient に加算され、誤った更新につながります。
- `loss.backward()` は、model parameter に対する loss の gradient を計算します。計算された gradient は、optimizer による weight の更新に使用されます。
- `optimizer.step()` は、計算された gradient と learning rate に基づいて model parameter を更新します。
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

Recurrent Neural Networks (RNNs) は、時系列や自然言語などのシーケンシャルデータを処理するために設計されたニューラルネットワークの一種です。従来のフィードフォワードニューラルネットワークとは異なり、RNNs には自身へループバックする接続があり、シーケンス内の以前の入力に関する情報を保持する隠れ状態を維持できます。

RNNs の主な構成要素は次のとおりです。
- **Recurrent Layers**: これらのレイヤーは入力シーケンスを一度に1タイムステップずつ処理し、現在の入力と以前の隠れ状態に基づいて隠れ状態を更新します。これにより、RNNs はデータ内の時間的依存関係を学習できます。
- **Hidden State**: 隠れ状態は、以前のタイムステップからの情報を要約するベクトルです。各タイムステップで更新され、現在の入力に対する予測に使用されます。
- **Output Layer**: 出力レイヤーは、隠れ状態に基づいて最終的な予測を生成します。多くの場合、RNNs は language modeling のようなタスクに使用されます。この場合、出力はシーケンス内の次の単語に対する確率分布です。

例えば、language model では、RNN が単語のシーケンス（例えば "The cat sat on the"）を処理し、以前の単語によって提供されたコンテキストに基づいて次の単語（この場合は "mat"）を予測します。

### Long Short-Term Memory (LSTM) and Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

RNNs は、language modeling、machine translation、speech recognition などのシーケンシャルデータを扱うタスクで特に効果的です。しかし、**vanishing gradients などの問題により、長距離依存関係の処理に苦労することがあります**。

これに対処するため、Long Short-Term Memory (LSTM) や Gated Recurrent Unit (GRU) のような特殊なアーキテクチャが開発されました。これらのアーキテクチャは情報の流れを制御する gating mechanisms を導入し、長距離依存関係をより効果的に捉えられるようにします。

- **LSTM**: LSTM networks は3つのゲート（input gate、forget gate、output gate）を使用して、cell state への情報の出入りを調整し、長いシーケンスにわたって情報を記憶または忘却できるようにします。input gate は、入力と以前の隠れ状態に基づいて追加する新しい情報の量を制御し、forget gate は破棄する情報の量を制御します。input gate と forget gate を組み合わせることで、新しい state が得られます。最後に、新しい cell state、入力、以前の隠れ状態を組み合わせることで、新しい hidden state も得られます。
- **GRU**: GRU networks は input gate と forget gate を単一の update gate に統合することで LSTM architecture を簡略化し、長距離依存関係を捉えながら計算効率を高めています。

## LLMs (Large Language Models)

Large Language Models (LLMs) は、自然言語処理タスクのために特別に設計された deep learning model の一種です。膨大な量のテキストデータで学習され、人間のようなテキストの生成、質問への回答、言語の翻訳、その他さまざまな言語関連タスクを実行できます。
LLMs は通常 transformer architectures に基づいており、self-attention mechanisms を使用してシーケンス内の単語間の関係を捉えます。これにより、コンテキストを理解し、一貫性のあるテキストを生成できます。

### Transformer Architecture <sup>[[4]](#references)</sup>
transformer architecture は、多くの LLMs の基盤です。これは encoder-decoder structure で構成され、encoder が入力シーケンスを処理し、decoder が出力シーケンスを生成します。transformer architecture の主な構成要素は次のとおりです。
- **Self-Attention Mechanism**: この mechanism により、モデルは表現を生成する際に、シーケンス内の異なる単語の重要度を評価できます。単語間の関係に基づいて attention scores を計算し、モデルが関連するコンテキストに集中できるようにします。
- **Multi-Head Attention**: この component は複数の attention heads を使用することで、モデルが単語間の複数の関係を捉えられるようにします。各 head は入力の異なる側面に焦点を当てます。
- **Positional Encoding**: transformers には単語の順序に関する組み込みの概念がないため、入力 embeddings に positional encoding を追加して、シーケンス内の単語の位置に関する情報を提供します。

## Diffusion Models <sup>[[5]](#references)</sup>
Diffusion models は、diffusion process をシミュレートすることでデータを生成するように学習する generative models の一種です。特に image generation などのタスクに効果的であり、近年人気が高まっています。
Diffusion models は、一連の diffusion steps を通じて、単純な noise distribution を複雑な data distribution へ段階的に変換することで動作します。Diffusion models の主な構成要素は次のとおりです。
- **Forward Diffusion Process**: この process はデータにノイズを徐々に追加し、単純な noise distribution へ変換します。forward diffusion process は通常、一連の noise levels によって定義され、各レベルはデータに追加される特定量のノイズに対応します。
- **Reverse Diffusion Process**: この process は forward diffusion process を逆転させるように学習し、データから段階的にノイズを除去して、対象の distribution から samples を生成します。reverse diffusion process は、noisy samples から元のデータを再構成するようモデルに促す loss function を使用して学習されます。

さらに、text prompt から画像を生成するために、diffusion models は通常、次の手順に従います。
1. **Text Encoding**: text prompt は、text encoder（例えば transformer-based model）を使用して latent representation にエンコードされます。この representation はテキストの意味的な内容を捉えます。
2. **Noise Sampling**: Gaussian distribution からランダムな noise vector がサンプリングされます。
3. **Diffusion Steps**: モデルは一連の diffusion steps を適用し、noise vector を text prompt に対応する画像へ段階的に変換します。各ステップでは、学習済みの transformations を適用して画像のノイズを除去します。

## References

- [1] [PyTorch - Neural Networks チュートリアル](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [ノイズ除去拡散確率モデル](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
