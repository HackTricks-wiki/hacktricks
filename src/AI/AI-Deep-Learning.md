# 深度学习

{{#include ../banners/hacktricks-training.md}}

## 深度学习

深度学习是机器学习的一个子集，它使用具有多个层（深度神经网络）的神经网络来建模数据中的复杂模式。它在多个领域取得了显著成功，包括计算机视觉、自然语言处理和语音识别。

### 神经网络

神经网络是深度学习的构建块。它们由互联的节点（神经元）组成，组织成层。每个神经元接收输入，应用加权和，并通过激活函数传递结果以产生输出。层可以分为以下几类：
- **输入层**：接收输入数据的第一层。
- **隐藏层**：对输入数据进行变换的中间层。隐藏层和每层中的神经元数量可以变化，从而导致不同的架构。
- **输出层**：产生网络输出的最后一层，例如分类任务中的类别概率。

### 激活函数

当一层神经元处理输入数据时，每个神经元对输入应用权重和偏置（`z = w * x + b`），其中 `w` 是权重，`x` 是输入，`b` 是偏置。然后，神经元的输出通过**激活函数引入非线性**到模型中。这个激活函数基本上指示下一个神经元“是否应该被激活以及激活的程度”。这使得网络能够学习数据中的复杂模式和关系，从而能够近似任何连续函数。

因此，激活函数将非线性引入神经网络，使其能够学习数据中的复杂关系。常见的激活函数包括：
- **Sigmoid**：将输入值映射到0和1之间的范围，通常用于二分类。
- **ReLU（修正线性单元）**：如果输入为正，则直接输出输入；否则，输出零。由于其简单性和在训练深度网络中的有效性，广泛使用。
- **Tanh**：将输入值映射到-1和1之间的范围，通常用于隐藏层。
- **Softmax**：将原始分数转换为概率，通常用于多类分类的输出层。

### 反向传播

反向传播是用于通过调整神经元之间连接的权重来训练神经网络的算法。它通过计算损失函数相对于每个权重的梯度，并在梯度的相反方向更新权重以最小化损失。反向传播涉及的步骤包括：

1. **前向传播**：通过将输入传递通过层并应用激活函数来计算网络的输出。
2. **损失计算**：使用损失函数（例如，回归的均方误差，分类的交叉熵）计算预测输出与真实目标之间的损失（误差）。
3. **反向传播**：使用微积分的链式法则计算损失相对于每个权重的梯度。
4. **权重更新**：使用优化算法（例如，随机梯度下降，Adam）更新权重以最小化损失。

## 卷积神经网络（CNNs）

卷积神经网络（CNNs）是一种专门设计用于处理网格状数据（如图像）的神经网络。由于其能够自动学习特征的空间层次结构，因此在计算机视觉任务中特别有效。

CNN的主要组成部分包括：
- **卷积层**：使用可学习的滤波器（内核）对输入数据应用卷积操作，以提取局部特征。每个滤波器在输入上滑动并计算点积，生成特征图。
- **池化层**：对特征图进行下采样，以减少其空间维度，同时保留重要特征。常见的池化操作包括最大池化和平均池化。
- **全连接层**：将一层中的每个神经元与下一层中的每个神经元连接，类似于传统神经网络。这些层通常在网络的末尾用于分类任务。

在CNN的**卷积层**中，我们还可以区分：
- **初始卷积层**：处理原始输入数据（例如图像）的第一卷积层，有助于识别基本特征，如边缘和纹理。
- **中间卷积层**：后续卷积层，基于初始层学习的特征，允许网络学习更复杂的模式和表示。
- **最终卷积层**：在全连接层之前的最后卷积层，捕获高级特征并为分类准备数据。

> [!TIP]
> CNN在图像分类、物体检测和图像分割任务中特别有效，因为它们能够学习网格状数据中特征的空间层次结构，并通过权重共享减少参数数量。
> 此外，它们在支持特征局部性原则的数据上表现更好，其中相邻数据（像素）更可能相关，而远离的像素可能不是其他类型数据（如文本）的情况。
> 此外，请注意，CNN能够识别甚至复杂的特征，但无法应用任何空间上下文，这意味着在图像不同部分发现的相同特征将是相同的。

### 定义CNN的示例

*在这里，您将找到如何在PyTorch中定义卷积神经网络（CNN）的描述，该网络以大小为48x48的RGB图像批次作为数据集，并使用卷积层和最大池化提取特征，随后是全连接层进行分类。*

这就是您如何在PyTorch中定义1个卷积层：`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`。

- `in_channels`：输入通道的数量。在RGB图像的情况下，这是3（每个颜色通道一个）。如果您使用的是灰度图像，则为1。

- `out_channels`：卷积层将学习的输出通道（滤波器）数量。这是一个超参数，您可以根据模型架构进行调整。

- `kernel_size`：卷积滤波器的大小。常见选择是3x3，这意味着滤波器将覆盖输入图像的3x3区域。这就像一个3×3×3的颜色印章，用于从输入通道生成输出通道：
1. 将该3×3×3的印章放在图像立方体的左上角。
2. 将每个权重乘以其下方的像素，将它们相加，添加偏置→您得到一个数字。
3. 将该数字写入位置（0, 0）的空白图中。
4. 将印章向右滑动一个像素（步幅=1），重复直到填满整个48×48的网格。

- `padding`：添加到输入每一侧的像素数量。填充有助于保持输入的空间维度，从而更好地控制输出大小。例如，对于一个3x3的内核和48x48像素的输入，填充1将使卷积操作后的输出大小保持不变（48x48）。这是因为填充在输入图像周围添加了1像素的边框，使内核能够在边缘滑动而不减少空间维度。

然后，这一层中的可训练参数数量为：
- (3x3x3（内核大小） + 1（偏置）) x 32（out_channels） = 896个可训练参数。

请注意，每个使用的内核添加了一个偏置（+1），因为每个卷积层的功能是学习输入的线性变换，这由以下方程表示：
```plaintext
Y = f(W * X + b)
```
`W` 是权重矩阵（学习到的滤波器，3x3x3 = 27 个参数），`b` 是偏置向量，对于每个输出通道为 +1。

请注意，`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` 的输出将是形状为 `(batch_size, 32, 48, 48)` 的张量，因为 32 是生成的新的 48x48 像素大小的通道数量。

然后，我们可以将这个卷积层连接到另一个卷积层，如：`self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`。

这将增加：(32x3x3（卷积核大小） + 1（偏置）) x 64（输出通道） = 18,496 个可训练参数，输出形状为 `(batch_size, 64, 48, 48)`。

正如你所看到的，**每增加一个卷积层，参数的数量迅速增长**，尤其是当输出通道的数量增加时。

控制使用数据量的一个选项是在每个卷积层后使用 **最大池化**。最大池化减少特征图的空间维度，这有助于减少参数数量和计算复杂性，同时保留重要特征。

可以声明为：`self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`。这基本上表示使用 2x2 像素的网格，并从每个网格中取最大值，以将特征图的大小减少一半。此外，`stride=2` 意味着池化操作每次移动 2 个像素，在这种情况下，防止池化区域之间的重叠。

使用这个池化层，经过第一个卷积层后的输出形状将是 `(batch_size, 64, 24, 24)`，在将 `self.pool1` 应用到 `self.conv2` 的输出后，大小减少到前一层的 1/4。

> [!TIP]
> 在卷积层后进行池化是很重要的，以减少特征图的空间维度，这有助于控制参数数量和计算复杂性，同时使初始参数学习重要特征。
> 你可以将池化层前的卷积视为从输入数据中提取特征（如线条、边缘），这些信息仍然会存在于池化输出中，但下一个卷积层将无法看到原始输入数据，只能看到池化输出，这是前一层的简化版本，包含了这些信息。
> 按照通常的顺序：`Conv → ReLU → Pool`，每个 2×2 的池化窗口现在处理特征激活（“边缘存在/不存在”），而不是原始像素强度。保留最强的激活确实保留了最显著的证据。

然后，在添加所需的卷积层和池化层后，我们可以将输出展平，以便将其输入到全连接层。这是通过将张量重塑为每个批次样本的 1D 向量来完成的：
```python
x = x.view(-1, 64*24*24)
```
通过这个包含所有由前面的卷积层和池化层生成的训练参数的1D向量，我们可以定义一个全连接层，如下所示：
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
将前一层的扁平输出映射到512个隐藏单元。

注意，这一层增加了`(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504`个可训练参数，这与卷积层相比是一个显著的增加。这是因为全连接层将一层中的每个神经元与下一层中的每个神经元连接，从而导致参数数量庞大。

最后，我们可以添加一个输出层以生成最终的类别logits：
```python
self.fc2 = nn.Linear(512, num_classes)
```
这将添加 `(512 + 1 (bias)) * num_classes` 可训练参数，其中 `num_classes` 是分类任务中的类别数量（例如，对于 GTSRB 数据集为 43）。

另一个常见做法是在全连接层之前添加一个 dropout 层以防止过拟合。这可以通过以下方式完成：
```python
self.dropout = nn.Dropout(0.5)
```
这一层在训练期间随机将一部分输入单元设置为零，这有助于通过减少对特定神经元的依赖来防止过拟合。

### CNN 代码示例
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
### CNN 代码训练示例

以下代码将生成一些训练数据并训练上面定义的 `MY_NET` 模型。一些有趣的值需要注意：

- `EPOCHS` 是模型在训练期间查看整个数据集的次数。如果 EPOCH 太小，模型可能学得不够；如果太大，可能会过拟合。
- `LEARNING_RATE` 是优化器的步长。较小的学习率可能导致收敛缓慢，而较大的学习率可能会超出最佳解并阻止收敛。
- `WEIGHT_DECAY` 是一个正则化项，通过惩罚大权重来帮助防止过拟合。

关于训练循环，这里有一些有趣的信息需要了解：
- `criterion = nn.CrossEntropyLoss()` 是用于多类分类任务的损失函数。它将 softmax 激活和交叉熵损失结合在一个函数中，使其适合训练输出类 logits 的模型。
- 如果模型预期输出其他类型的输出，如二元分类或回归，我们将使用不同的损失函数，如 `nn.BCEWithLogitsLoss()` 用于二元分类或 `nn.MSELoss()` 用于回归。
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` 初始化了 Adam 优化器，这是训练深度学习模型的热门选择。它根据梯度的一阶和二阶矩调整每个参数的学习率。
- 其他优化器如 `optim.SGD`（随机梯度下降）或 `optim.RMSprop` 也可以使用，具体取决于训练任务的特定要求。
- `model.train()` 方法将模型设置为训练模式，使得像 dropout 和批量归一化这样的层在训练期间与评估期间的行为不同。
- `optimizer.zero_grad()` 在反向传播之前清除所有优化张量的梯度，这是必要的，因为在 PyTorch 中，梯度默认是累积的。如果不清除，前几次迭代的梯度将被添加到当前梯度中，导致更新不正确。
- `loss.backward()` 计算损失相对于模型参数的梯度，然后优化器使用这些梯度来更新权重。
- `optimizer.step()` 根据计算出的梯度和学习率更新模型参数。
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
## 循环神经网络 (RNNs)

循环神经网络 (RNNs) 是一种专为处理序列数据（如时间序列或自然语言）而设计的神经网络类别。与传统的前馈神经网络不同，RNNs 具有自我回环的连接，使其能够保持一个隐藏状态，该状态捕捉序列中先前输入的信息。

RNNs 的主要组成部分包括：
- **循环层**：这些层一次处理一个时间步的输入序列，根据当前输入和先前的隐藏状态更新其隐藏状态。这使得 RNNs 能够学习数据中的时间依赖性。
- **隐藏状态**：隐藏状态是一个向量，汇总了先前时间步的信息。它在每个时间步更新，并用于对当前输入进行预测。
- **输出层**：输出层根据隐藏状态生成最终预测。在许多情况下，RNNs 用于语言建模等任务，其中输出是序列中下一个单词的概率分布。

例如，在语言模型中，RNN 处理一个单词序列，例如 "The cat sat on the"，并根据前面单词提供的上下文预测下一个单词，在这种情况下是 "mat"。

### 长短期记忆 (LSTM) 和门控循环单元 (GRU)

RNNs 在处理涉及序列数据的任务（如语言建模、机器翻译和语音识别）时特别有效。然而，由于 **梯度消失等问题，它们在处理长范围依赖性时可能会遇到困难**。

为了解决这个问题，开发了长短期记忆 (LSTM) 和门控循环单元 (GRU) 等专门架构。这些架构引入了控制信息流动的门控机制，使其能够更有效地捕捉长范围依赖性。

- **LSTM**：LSTM 网络使用三个门（输入门、遗忘门和输出门）来调节信息在单元状态中的流动，使其能够在长序列中记住或遗忘信息。输入门根据输入和先前的隐藏状态控制添加多少新信息，遗忘门控制丢弃多少信息。结合输入门和遗忘门，我们得到新的状态。最后，将新的单元状态与输入和先前的隐藏状态结合，我们也得到新的隐藏状态。
- **GRU**：GRU 网络通过将输入门和遗忘门合并为一个更新门来简化 LSTM 架构，使其在计算上更高效，同时仍能捕捉长范围依赖性。

## LLMs (大型语言模型)

大型语言模型 (LLMs) 是一种专门为自然语言处理任务设计的深度学习模型。它们在大量文本数据上进行训练，能够生成类人文本、回答问题、翻译语言以及执行各种其他与语言相关的任务。
LLMs 通常基于变换器架构，该架构使用自注意力机制来捕捉序列中单词之间的关系，使其能够理解上下文并生成连贯的文本。

### 变换器架构
变换器架构是许多 LLMs 的基础。它由编码器-解码器结构组成，其中编码器处理输入序列，解码器生成输出序列。变换器架构的关键组成部分包括：
- **自注意力机制**：该机制允许模型在生成表示时权衡序列中不同单词的重要性。它根据单词之间的关系计算注意力分数，使模型能够关注相关上下文。
- **多头注意力**：该组件允许模型通过使用多个注意力头来捕捉单词之间的多种关系，每个头关注输入的不同方面。
- **位置编码**：由于变换器没有内置的单词顺序概念，因此在输入嵌入中添加位置编码，以提供有关序列中单词位置的信息。

## 扩散模型
扩散模型是一类生成模型，通过模拟扩散过程来学习生成数据。它们在图像生成等任务中特别有效，并在近年来获得了广泛关注。
扩散模型通过逐渐将简单的噪声分布转变为复杂的数据分布，经过一系列扩散步骤。扩散模型的关键组成部分包括：
- **前向扩散过程**：该过程逐渐向数据添加噪声，将其转变为简单的噪声分布。前向扩散过程通常由一系列噪声水平定义，每个水平对应于添加到数据中的特定噪声量。
- **反向扩散过程**：该过程学习反转前向扩散过程，逐渐去噪数据以从目标分布生成样本。反向扩散过程使用损失函数进行训练，该函数鼓励模型从噪声样本中重建原始数据。

此外，为了从文本提示生成图像，扩散模型通常遵循以下步骤：
1. **文本编码**：使用文本编码器（例如基于变换器的模型）将文本提示编码为潜在表示。该表示捕捉文本的语义含义。
2. **噪声采样**：从高斯分布中采样一个随机噪声向量。
3. **扩散步骤**：模型应用一系列扩散步骤，逐渐将噪声向量转变为与文本提示对应的图像。每一步涉及应用学习到的变换以去噪图像。

{{#include ../banners/hacktricks-training.md}}
