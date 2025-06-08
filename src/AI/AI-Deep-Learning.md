# ディープラーニング

{{#include ../banners/hacktricks-training.md}}

## ディープラーニング

ディープラーニングは、複数の層を持つニューラルネットワーク（深層ニューラルネットワーク）を使用してデータの複雑なパターンをモデル化する機械学習のサブセットです。コンピュータビジョン、自然言語処理、音声認識など、さまざまな分野で驚異的な成功を収めています。

### ニューラルネットワーク

ニューラルネットワークは、ディープラーニングの基本構成要素です。これらは、層に組織された相互接続されたノード（ニューロン）で構成されています。各ニューロンは入力を受け取り、重み付き和を適用し、活性化関数を通じて結果を出力します。層は以下のように分類できます：
- **入力層**：入力データを受け取る最初の層。
- **隠れ層**：入力データに変換を行う中間層。隠れ層の数や各層のニューロンの数は異なる場合があり、異なるアーキテクチャを生み出します。
- **出力層**：ネットワークの出力を生成する最終層で、分類タスクにおけるクラス確率などを含みます。

### 活性化関数

ニューロンの層が入力データを処理する際、各ニューロンは入力に重みとバイアスを適用します（`z = w * x + b`）、ここで `w` は重み、`x` は入力、`b` はバイアスです。ニューロンの出力は、モデルに非線形性を導入するために**活性化関数を通過します**。この活性化関数は、次のニューロンが「活性化されるべきか、どの程度か」を示します。これにより、ネットワークはデータ内の複雑なパターンや関係を学習し、任意の連続関数を近似できるようになります。

したがって、活性化関数はニューラルネットワークに非線形性を導入し、データ内の複雑な関係を学習できるようにします。一般的な活性化関数には以下が含まれます：
- **シグモイド**：入力値を0と1の範囲にマッピングし、主に二項分類に使用されます。
- **ReLU（Rectified Linear Unit）**：入力が正の場合はそのまま出力し、そうでない場合はゼロを出力します。シンプルさと深層ネットワークのトレーニングにおける効果的な特性から広く使用されています。
- **Tanh**：入力値を-1と1の範囲にマッピングし、主に隠れ層で使用されます。
- **Softmax**：生のスコアを確率に変換し、主に多クラス分類の出力層で使用されます。

### バックプロパゲーション

バックプロパゲーションは、ニューロン間の接続の重みを調整することによってニューラルネットワークをトレーニングするために使用されるアルゴリズムです。これは、損失関数の勾配を各重みに対して計算し、損失を最小化するために勾配の逆方向に重みを更新することによって機能します。バックプロパゲーションに関わるステップは以下の通りです：

1. **フォワードパス**：入力を層を通して渡し、活性化関数を適用してネットワークの出力を計算します。
2. **損失計算**：予測出力と真のターゲットとの間の損失（誤差）を損失関数（例：回帰の平均二乗誤差、分類のクロスエントロピー）を使用して計算します。
3. **バックワードパス**：微分法則を使用して、各重みに対する損失の勾配を計算します。
4. **重み更新**：最適化アルゴリズム（例：確率的勾配降下法、Adam）を使用して損失を最小化するために重みを更新します。

## 畳み込みニューラルネットワーク（CNN）

畳み込みニューラルネットワーク（CNN）は、画像などのグリッド状データを処理するために設計された特殊なタイプのニューラルネットワークです。これらは、特徴の空間的階層を自動的に学習する能力により、コンピュータビジョンタスクで特に効果的です。

CNNの主な構成要素には以下が含まれます：
- **畳み込み層**：学習可能なフィルター（カーネル）を使用して入力データに畳み込み操作を適用し、局所的な特徴を抽出します。各フィルターは入力の上をスライドし、ドット積を計算して特徴マップを生成します。
- **プーリング層**：特徴マップの空間的次元を減少させながら重要な特徴を保持します。一般的なプーリング操作には最大プーリングと平均プーリングがあります。
- **全結合層**：1つの層のすべてのニューロンを次の層のすべてのニューロンに接続し、従来のニューラルネットワークに似ています。これらの層は通常、分類タスクのためにネットワークの最後に使用されます。

CNNの**`畳み込み層`**内では、以下のように区別できます：
- **初期畳み込み層**：生の入力データ（例：画像）を処理し、エッジやテクスチャなどの基本的な特徴を特定するのに役立つ最初の畳み込み層。
- **中間畳み込み層**：初期層によって学習された特徴を基に構築され、ネットワークがより複雑なパターンや表現を学習できるようにする後続の畳み込み層。
- **最終畳み込み層**：全結合層の前の最後の畳み込み層で、高レベルの特徴をキャプチャし、分類のためにデータを準備します。

> [!TIP]
> CNNは、グリッド状データ内の特徴の空間的階層を学習し、重みの共有を通じてパラメータの数を減少させる能力により、画像分類、物体検出、画像セグメンテーションタスクに特に効果的です。
> さらに、隣接データ（ピクセル）が遠くのピクセルよりも関連している可能性が高いという特徴の局所性原則を支持するデータでより良く機能しますが、テキストのような他のタイプのデータではそうではないかもしれません。
> さらに、CNNが複雑な特徴を特定できる一方で、空間的文脈を適用できないことに注意してください。つまり、画像の異なる部分で見つかった同じ特徴は同じになります。

### CNNを定義する例

*ここでは、サイズ48x48のRGB画像のバッチをデータセットとして使用し、特徴を抽出するために畳み込み層と最大プーリングを使用し、分類のために全結合層を続ける畳み込みニューラルネットワーク（CNN）をPyTorchで定義する方法について説明します。*

これがPyTorchで1つの畳み込み層を定義する方法です：`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`。

- `in_channels`：入力チャネルの数。RGB画像の場合、これは3（各色チャネルの1つ）です。グレースケール画像を扱う場合、これは1になります。

- `out_channels`：畳み込み層が学習する出力チャネル（フィルター）の数。これはモデルアーキテクチャに基づいて調整できるハイパーパラメータです。

- `kernel_size`：畳み込みフィルターのサイズ。一般的な選択肢は3x3で、これはフィルターが入力画像の3x3の領域をカバーすることを意味します。これは、in_channelsからout_channelsを生成するために使用される3×3×3のカラースタンプのようなものです：
1. その3×3×3のスタンプを画像キューブの左上隅に置きます。
2. 各重みをその下のピクセルで掛け算し、すべてを加算し、バイアスを加えます → 1つの数値が得られます。
3. その数値を位置(0, 0)の空白マップに書き込みます。
4. スタンプを右に1ピクセルスライドさせ（ストライド=1）、48×48のグリッド全体を埋めるまで繰り返します。

- `padding`：入力の各側に追加されるピクセルの数。パディングは入力の空間的次元を保持するのに役立ち、出力サイズをより制御できるようにします。たとえば、3x3のカーネルと48x48ピクセルの入力で、パディングが1の場合、畳み込み操作の後に出力サイズは同じ（48x48）のままになります。これは、パディングが入力画像の周りに1ピクセルのボーダーを追加し、カーネルがエッジをスライドできるようにするためです。

次に、この層の学習可能なパラメータの数は：
- (3x3x3（カーネルサイズ） + 1（バイアス）) x 32（out_channels） = 896の学習可能なパラメータです。

各畳み込み層の機能は、入力の線形変換を学習することであり、これは次の方程式で表されます：
```plaintext
Y = f(W * X + b)
```
`W`は重み行列（学習されたフィルタ、3x3x3 = 27パラメータ）、`b`は各出力チャネルに対して+1のバイアスベクトルです。

`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`の出力は、形状が`(batch_size, 32, 48, 48)`のテンソルになります。これは、32が生成された新しいチャネルの数で、サイズは48x48ピクセルです。

次に、この畳み込み層を別の畳み込み層に接続することができます: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`。

これにより、(32x3x3（カーネルサイズ） + 1（バイアス）) x 64（出力チャネル） = 18,496の学習可能なパラメータが追加され、出力の形状は`(batch_size, 64, 48, 48)`になります。

**パラメータの数は、各追加の畳み込み層で急速に増加します**、特に出力チャネルの数が増えるにつれて。

データの使用量を制御するための1つのオプションは、各畳み込み層の後に**最大プーリング**を使用することです。最大プーリングは特徴マップの空間的次元を減少させ、重要な特徴を保持しながらパラメータの数と計算の複雑さを減少させるのに役立ちます。

これは次のように宣言できます: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`。これは基本的に2x2ピクセルのグリッドを使用し、各グリッドから最大値を取得して特徴マップのサイズを半分に減少させることを示します。さらに、`stride=2`は、プーリング操作が2ピクセルずつ移動することを意味し、この場合、プーリング領域間の重複を防ぎます。

このプーリング層を使用すると、最初の畳み込み層の後の出力形状は、`self.conv2`の出力に`self.pool1`を適用した後、`(batch_size, 64, 24, 24)`になります。これは、前の層のサイズを1/4に減少させます。

> [!TIP]
> 畳み込み層の後にプーリングを行うことは、特徴マップの空間的次元を減少させるために重要です。これにより、パラメータの数と計算の複雑さを制御しながら、初期パラメータが重要な特徴を学習するのに役立ちます。
> プーリング層の前の畳み込みを、入力データから特徴を抽出する方法として見ることができます（線やエッジのように）。この情報はプールされた出力にも存在しますが、次の畳み込み層は元の入力データを見ることができず、プールされた出力のみを見ます。これは、前の層の情報を持つ縮小版です。
> 通常の順序では: `Conv → ReLU → Pool`、各2×2プーリングウィンドウは、特徴の活性化（「エッジが存在する/しない」）と対峙し、生のピクセル強度ではありません。最も強い活性化を保持することは、最も顕著な証拠を保持することを本当に意味します。

その後、必要なだけの畳み込み層とプーリング層を追加したら、出力をフラット化して全結合層に供給できます。これは、バッチ内の各サンプルのためにテンソルを1Dベクトルに再形成することで行われます:
```python
x = x.view(-1, 64*24*24)
```
この1Dベクトルは、前の畳み込み層とプーリング層によって生成されたすべてのトレーニングパラメータを含んでおり、次のように全結合層を定義できます:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
前の層のフラット化された出力を取り、それを512の隠れユニットにマッピングします。

この層が追加したパラメータ数は `(64 * 24 * 24 + 1 (バイアス)) * 512 = 3,221,504` であり、畳み込み層と比較して大幅な増加です。これは、全結合層が1つの層のすべてのニューロンを次の層のすべてのニューロンに接続するため、大量のパラメータが生じるためです。

最後に、最終的なクラスロジットを生成するための出力層を追加できます：
```python
self.fc2 = nn.Linear(512, num_classes)
```
これにより、`(512 + 1 (バイアス)) * num_classes` の学習可能なパラメータが追加されます。ここで、`num_classes` は分類タスクのクラス数です（例：GTSRBデータセットの場合は43）。

もう一つの一般的な手法は、過学習を防ぐために全結合層の前にドロップアウト層を追加することです。これは次のように行うことができます：
```python
self.dropout = nn.Dropout(0.5)
```
この層は、トレーニング中に入力ユニットの一部をランダムにゼロに設定します。これにより、特定のニューロンへの依存を減らすことで、オーバーフィッティングを防ぐのに役立ちます。

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
### CNN コードトレーニング例

以下のコードは、いくつかのトレーニングデータを生成し、上で定義した `MY_NET` モデルをトレーニングします。注目すべき興味深い値は次のとおりです：

- `EPOCHS` は、モデルがトレーニング中に全データセットを見る回数です。EPOCH が小さすぎると、モデルは十分に学習できない可能性があります。大きすぎると、過学習する可能性があります。
- `LEARNING_RATE` はオプティマイザのステップサイズです。小さな学習率は収束が遅くなる可能性があり、大きすぎると最適解をオーバーシュートし、収束を妨げる可能性があります。
- `WEIGHT_DECAY` は、大きな重みをペナルティすることによって過学習を防ぐのに役立つ正則化項です。

トレーニングループに関して知っておくべき興味深い情報は次のとおりです：
- `criterion = nn.CrossEntropyLoss()` は、マルチクラス分類タスクに使用される損失関数です。これは、ソフトマックス活性化とクロスエントロピー損失を1つの関数に統合しており、クラスロジットを出力するモデルのトレーニングに適しています。
- モデルがバイナリ分類や回帰などの他のタイプの出力を出力することが期待される場合、バイナリ分類には `nn.BCEWithLogitsLoss()`、回帰には `nn.MSELoss()` のような異なる損失関数を使用します。
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` は、深層学習モデルのトレーニングに人気のある選択肢であるAdamオプティマイザを初期化します。これは、勾配の1次および2次モーメントに基づいて各パラメータの学習率を適応させます。
- `optim.SGD`（確率的勾配降下法）や `optim.RMSprop` のような他のオプティマイザも、トレーニングタスクの特定の要件に応じて使用できます。
- `model.train()` メソッドは、モデルをトレーニングモードに設定し、ドロップアウトやバッチ正規化のようなレイヤーが評価時とは異なる動作をするようにします。
- `optimizer.zero_grad()` は、バックワードパスの前にすべての最適化されたテンソルの勾配をクリアします。これは、PyTorchでは勾配がデフォルトで蓄積されるため、必要です。クリアしないと、前のイテレーションの勾配が現在の勾配に加算され、不正確な更新が行われます。
- `loss.backward()` は、モデルパラメータに対する損失の勾配を計算し、これをオプティマイザが重みを更新するために使用します。
- `optimizer.step()` は、計算された勾配と学習率に基づいてモデルパラメータを更新します。
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
## 再帰型ニューラルネットワーク (RNN)

再帰型ニューラルネットワーク (RNN) は、時系列や自然言語などの逐次データを処理するために設計されたニューラルネットワークの一種です。従来のフィードフォワードニューラルネットワークとは異なり、RNN には自己ループする接続があり、これによりシーケンス内の以前の入力に関する情報を保持する隠れ状態を維持できます。

RNN の主な構成要素は次のとおりです：
- **再帰層**：これらの層は、入力シーケンスを1つのタイムステップずつ処理し、現在の入力と前の隠れ状態に基づいて隠れ状態を更新します。これにより、RNN はデータ内の時間的依存関係を学習できます。
- **隠れ状態**：隠れ状態は、以前のタイムステップからの情報を要約したベクトルです。各タイムステップで更新され、現在の入力に対する予測を行うために使用されます。
- **出力層**：出力層は、隠れ状態に基づいて最終的な予測を生成します。多くの場合、RNN は言語モデルのようなタスクに使用され、出力はシーケンス内の次の単語に対する確率分布です。

例えば、言語モデルでは、RNN は「The cat sat on the」という単語のシーケンスを処理し、前の単語によって提供されたコンテキストに基づいて次の単語を予測します。この場合は「mat」です。

### 長短期記憶 (LSTM) とゲート付き再帰ユニット (GRU)

RNN は、言語モデル、機械翻訳、音声認識などの逐次データを扱うタスクに特に効果的です。しかし、**消失勾配のような問題により、長期依存関係に苦労することがあります**。

これに対処するために、長短期記憶 (LSTM) やゲート付き再帰ユニット (GRU) のような特殊なアーキテクチャが開発されました。これらのアーキテクチャは、情報の流れを制御するゲーティングメカニズムを導入し、長期依存関係をより効果的に捉えることができます。

- **LSTM**：LSTM ネットワークは、セル状態の出入りの情報の流れを調整するために、3つのゲート（入力ゲート、忘却ゲート、出力ゲート）を使用し、長いシーケンスにわたって情報を記憶または忘却することを可能にします。入力ゲートは、入力と前の隠れ状態に基づいて新しい情報をどれだけ追加するかを制御し、忘却ゲートはどれだけの情報を破棄するかを制御します。入力ゲートと忘却ゲートを組み合わせることで新しい状態が得られます。最後に、新しいセル状態と入力、前の隠れ状態を組み合わせることで新しい隠れ状態も得られます。
- **GRU**：GRU ネットワークは、入力ゲートと忘却ゲートを単一の更新ゲートに統合することで LSTM アーキテクチャを簡素化し、計算効率を高めつつ長期依存関係を捉えます。

## LLM (大規模言語モデル)

大規模言語モデル (LLM) は、自然言語処理タスクのために特別に設計された深層学習モデルの一種です。膨大なテキストデータで訓練され、人間のようなテキストを生成したり、質問に答えたり、言語を翻訳したり、さまざまな言語関連のタスクを実行したりできます。
LLM は通常、トランスフォーマーアーキテクチャに基づいており、自己注意メカニズムを使用してシーケンス内の単語間の関係を捉え、コンテキストを理解し、一貫したテキストを生成します。

### トランスフォーマーアーキテクチャ
トランスフォーマーアーキテクチャは、多くの LLM の基盤です。これは、エンコーダー-デコーダー構造で構成されており、エンコーダーが入力シーケンスを処理し、デコーダーが出力シーケンスを生成します。トランスフォーマーアーキテクチャの主要な構成要素は次のとおりです：
- **自己注意メカニズム**：このメカニズムにより、モデルは表現を生成する際にシーケンス内の異なる単語の重要性を重み付けできます。単語間の関係に基づいて注意スコアを計算し、モデルが関連するコンテキストに焦点を当てることを可能にします。
- **マルチヘッド注意**：このコンポーネントは、モデルが複数の注意ヘッドを使用して単語間の複数の関係を捉えることを可能にし、それぞれが入力の異なる側面に焦点を当てます。
- **位置エンコーディング**：トランスフォーマーには単語の順序に関する組み込みの概念がないため、位置エンコーディングが入力埋め込みに追加され、シーケンス内の単語の位置に関する情報を提供します。

## 拡散モデル
拡散モデルは、拡散プロセスをシミュレートすることによってデータを生成することを学習する生成モデルの一種です。画像生成のようなタスクに特に効果的で、近年人気を集めています。
拡散モデルは、単純なノイズ分布を一連の拡散ステップを通じて複雑なデータ分布に徐々に変換することによって機能します。拡散モデルの主要な構成要素は次のとおりです：
- **前方拡散プロセス**：このプロセスは、データに徐々にノイズを追加し、単純なノイズ分布に変換します。前方拡散プロセスは、各レベルがデータに追加される特定の量のノイズに対応する一連のノイズレベルによって定義されます。
- **逆拡散プロセス**：このプロセスは、前方拡散プロセスを逆転させることを学習し、データを徐々にデノイズしてターゲット分布からサンプルを生成します。逆拡散プロセスは、ノイズのあるサンプルから元のデータを再構築するようにモデルを促す損失関数を使用して訓練されます。

さらに、テキストプロンプトから画像を生成するために、拡散モデルは通常次のステップに従います：
1. **テキストエンコーディング**：テキストプロンプトは、テキストエンコーダー（例：トランスフォーマーベースのモデル）を使用して潜在表現にエンコードされます。この表現は、テキストの意味的な意味を捉えます。
2. **ノイズサンプリング**：ガウス分布からランダムなノイズベクトルがサンプリングされます。
3. **拡散ステップ**：モデルは一連の拡散ステップを適用し、ノイズベクトルをテキストプロンプトに対応する画像に徐々に変換します。各ステップでは、画像をデノイズするために学習された変換を適用します。

{{#include ../banners/hacktricks-training.md}}
