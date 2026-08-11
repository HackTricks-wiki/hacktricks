# 深度学习

{{#include ../banners/hacktricks-training.md}}

## 深度学习 <sup>[[1]](#references)</sup>

深度学习是 machine learning 的一个子集，它使用具有多个层的神经网络（深度神经网络）来对数据中的复杂模式进行建模。它已在多个领域取得了显著成功，包括 computer vision、natural language processing 和 speech recognition。

### 神经网络

神经网络是深度学习的构建模块。它们由按层组织的互连节点（神经元）组成。每个神经元接收输入，应用加权和，并通过 activation function 传递结果以生成输出。这些层可以分类如下：
- **输入层**：接收输入数据的第一层。
- **隐藏层**：对输入数据执行转换的中间层。隐藏层的数量以及每层中的神经元数量可以变化，从而形成不同的架构。
- **输出层**：生成网络输出的最后一层，例如 classification 任务中的类别概率。


### 激活函数

当一层神经元处理输入数据时，每个神经元都会对输入应用权重和偏置（`z = w * x + b`），其中 `w` 是权重，`x` 是输入，`b` 是偏置。随后，神经元的输出会经过一个**activation function，以向模型引入非线性**。这个 activation function 基本上表示下一个神经元“是否应该被激活，以及激活程度”。这使网络能够学习数据中的复杂模式和关系，从而使其能够逼近任意连续函数。

因此，activation functions 会向神经网络引入非线性，使其能够学习数据中的复杂关系。常见的 activation functions 包括：
- **Sigmoid**：将输入值映射到 0 和 1 之间的范围，通常用于 binary classification。
- **ReLU (Rectified Linear Unit)**：如果输入为正，则直接输出输入；否则输出零。由于其简单且在训练 deep networks 时效果良好，因此被广泛使用。
- **Tanh**：将输入值映射到 -1 和 1 之间的范围，通常用于隐藏层。
- **Softmax**：将原始分数转换为概率，通常用于 multi-class classification 的输出层。

### 反向传播

Backpropagation 是用于训练神经网络的算法，通过调整神经元之间连接的权重来实现训练。它通过计算 loss function 相对于每个权重的梯度，并沿梯度的相反方向更新权重，以最小化 loss。Backpropagation 涉及的步骤如下：

1. **前向传播**：将输入传过各层并应用 activation functions，计算网络的输出。
2. **Loss 计算**：使用 loss function 计算预测输出与真实目标之间的 loss（误差）（例如，回归中的 mean squared error，以及 classification 中的 cross-entropy）。
3. **反向传播**：使用微积分的 chain rule，计算 loss 相对于每个权重的梯度。
4. **权重更新**：使用 optimization algorithm（例如 stochastic gradient descent、Adam）更新权重，以最小化 loss。

## 卷积神经网络（CNNs） <sup>[[2]](#references)</sup>

卷积神经网络（CNNs）是一种专门用于处理网格状数据（例如图像）的神经网络。由于能够自动学习特征的空间层次结构，它们在 computer vision 任务中尤其有效。

CNNs 的主要组件包括：
- **卷积层**：使用可学习的 filters（kernels）对输入数据执行卷积操作，以提取局部特征。每个 filter 会在输入上滑动并计算点积，从而生成 feature map。
- **池化层**：对 feature maps 进行下采样，以减少其空间维度，同时保留重要特征。常见的池化操作包括 max pooling 和 average pooling。
- **全连接层**：将一层中的每个神经元连接到下一层中的每个神经元，类似于传统神经网络。这些层通常在网络末端用于 classification 任务。

在 CNN 的 **`Convolutional Layers`** 内部，我们还可以进行如下区分：
- **初始卷积层**：处理原始输入数据（例如图像）的第一层卷积层，有助于识别边缘和纹理等基础特征。
- **中间卷积层**：后续的卷积层，在初始层学习到的特征之上继续构建，使网络能够学习更复杂的模式和表示。
- **最终卷积层**：全连接层之前的最后几个卷积层，用于捕获高级特征，并为 classification 准备数据。

> [!TIP]
> CNNs 特别适用于 image classification、object detection 和 image segmentation 任务，这是因为它们能够学习网格状数据中的特征空间层次结构，并通过权重共享减少参数数量。
> 此外，它们在支持特征局部性原则的数据上表现更好：相邻数据（像素）之间比相距较远的像素更可能存在关联，而 text 等其他类型的数据可能并不具备这一特性。
> 另外需要注意的是，CNNs 能够识别复杂特征，但无法应用任何空间上下文，这意味着在图像不同位置发现的相同特征将被视为相同。

### 定义 CNN 的示例

*这里将介绍如何在 PyTorch 中定义一个 Convolutional Neural Network (CNN)：它以大小为 48x48 的 RGB 图像批次作为数据集，使用卷积层和 maxpool 提取特征，然后使用全连接层进行 classification。*

以下是在 PyTorch 中定义 1 个卷积层的方法：`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`。

- `in_channels`：输入通道的数量。对于 RGB 图像，该值为 3（每种颜色通道各一个）。如果处理的是灰度图像，则该值为 1。

- `out_channels`：输出通道（filters）的数量，即卷积层将学习的 filters 数量。这是一个 hyperparameter，可以根据模型架构进行调整。

- `kernel_size`：卷积 filter 的大小。常见选择是 3x3，这意味着 filter 将覆盖输入图像中的 3x3 区域。它就像一个 3×3×3 的彩色印章，用于从 in_channels 生成 out_channels：
1. 将这个 3×3×3 的印章放在图像立方体的左上角。
2. 将每个权重与其下方的像素相乘，把所有结果相加，再加上 bias → 得到一个数字。
3. 将这个数字写入空白 map 的位置 (0, 0)。
4. 将印章向右移动一个像素（stride = 1），并重复操作，直到填满整个 48×48 网格。

- `padding`：添加到输入每一侧的像素数量。Padding 有助于保留输入的空间维度，从而更好地控制输出大小。例如，对于 3x3 kernel 和 48x48 像素的输入，padding 为 1 将使卷积操作后的输出大小保持不变（48x48）。这是因为 padding 会在输入图像周围添加 1 像素的边框，使 kernel 能够覆盖边缘，同时不会缩小空间维度。

然后，该层中的可训练参数数量为：
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 个可训练参数。

请注意，每使用一个 kernel 都会添加一个 Bias (+1)，因为每个卷积层的作用是学习输入的线性变换，其表示方式为以下公式：
```plaintext
Y = f(W * X + b)
```
其中，`W` 是权重矩阵（学习到的 filters，3x3x3 = 27 个参数），`b` 是偏置向量，每个输出 channel 的值为 +1。

注意，`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` 的输出将是形状为 `(batch_size, 32, 48, 48)` 的 tensor，因为 32 是新生成的 channels 数量，每个 channel 的大小为 48x48 pixels。

然后，我们可以将这一 convolutional layer 连接到另一个 convolutional layer，例如：`self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`。

这将增加：(32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 个可训练参数，并生成形状为 `(batch_size, 64, 48, 48)` 的输出。

正如你所看到的，**每增加一个 convolutional layer，参数数量都会快速增长**，尤其是在 output channels 数量增加时。

控制数据量的一种方法是在每个 convolutional layer 后使用 **max pooling**。Max pooling 会缩小 feature maps 的空间维度，这有助于减少参数数量和计算复杂度，同时保留重要 features。

它可以声明为：`self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`。这基本表示使用一个 2x2 pixels 的网格，并从每个网格中取最大值，从而将 feature map 的大小缩小一半。此外，`stride=2` 表示 pooling 操作每次移动 2 pixels，在本例中可以防止 pooling 区域之间发生重叠。

使用这一 pooling layer 后，将 `self.pool1` 应用于 `self.conv2` 的输出时，第一次 convolutional layer 后的输出形状将变为 `(batch_size, 64, 24, 24)`，大小缩小为上一 layer 的 1/4。

> [!TIP]
> 在 convolutional layers 之后进行 pooling 非常重要，因为它可以缩小 feature maps 的空间维度，有助于控制参数数量和计算复杂度，同时使初始参数能够学习重要 features。
>你可以将 pooling layer 之前的 convolutions 看作从输入数据中提取 features（例如 lines、edges）的方法。这些信息仍会存在于 pooled output 中，但下一个 convolutional layer 将无法看到原始输入数据，只能看到 pooled output；后者是上一 layer 的缩减版本，但仍包含这些信息。
>在通常的顺序 `Conv → ReLU → Pool` 中，每个 2×2 pooling window 现在处理的是 feature activations（“edge present / not”），而不是原始 pixel intensities。保留最强的 activation 确实保留了最显著的 evidence。

然后，在添加所需数量的 convolutional 和 pooling layers 后，我们可以将输出 flatten，以便将其输入 fully connected layers。具体做法是将 tensor 重塑为 batch 中每个 sample 对应的 1D vector：
```python
x = x.view(-1, 64*24*24)
```
有了这个由前面的 convolutional 和 pooling layers 生成的、包含所有 training parameters 的 1D vector，我们可以定义一个 fully connected layer，如下所示：
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
它会将上一层的扁平化输出映射到 512 个 hidden units。

请注意，该层新增了 `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` 个可训练参数，相比卷积层有显著增加。这是因为 fully connected 层会将一层中的每个神经元连接到下一层中的每个神经元，从而产生大量参数。

最后，我们可以添加一个输出层来生成最终的 class logits：
```python
self.fc2 = nn.Linear(512, num_classes)
```
这将添加 `(512 + 1 (bias)) * num_classes` 个可训练参数，其中 `num_classes` 是分类任务中的类别数量（例如，GTSRB 数据集有 43 个类别）。

另一个常见做法是在 fully connected layers 之前添加 dropout layer，以防止 overfitting。可以通过以下方式实现：
```python
self.dropout = nn.Dropout(0.5)
```
该层在训练期间随机将一部分输入单元设置为零，通过减少对特定神经元的依赖来帮助防止过拟合。

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
### CNN Code training 示例

以下代码将生成一些训练数据，并训练上文定义的 `MY_NET` 模型。以下是一些值得注意的参数：

- `EPOCHS` 表示模型在训练期间完整遍历整个数据集的次数。如果 EPOCH 太小，模型可能学习不足；如果太大，则可能发生过拟合。
- `LEARNING_RATE` 是 optimizer 的步长。较小的 learning rate 可能导致收敛缓慢，而较大的 learning rate 可能越过最优解，从而无法收敛。
- `WEIGHT_DECAY` 是一种 regularization 项，通过惩罚较大的权重来帮助防止过拟合。

关于训练循环，以下是一些需要了解的重要信息：
- `criterion = nn.CrossEntropyLoss()` 是用于 multi-class classification 任务的 loss function。它将 softmax activation 和 cross-entropy loss 合并到一个函数中，因此适合训练输出 class logits 的模型。
- 如果模型需要输出其他类型的结果，例如 binary classification 或 regression，我们会使用不同的 loss function，例如用于 binary classification 的 `nn.BCEWithLogitsLoss()`，或用于 regression 的 `nn.MSELoss()`。
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` 会初始化 Adam optimizer。Adam 是训练 deep learning 模型时常用的选择，它会根据 gradients 的一阶和二阶矩为每个 parameter 调整 learning rate。
- 根据训练任务的具体要求，也可以使用其他 optimizer，例如 `optim.SGD`（Stochastic Gradient Descent）或 `optim.RMSprop`。
- `model.train()` 方法会将模型设置为 training mode，使 dropout 和 batch normalization 等 layers 在 training 期间与 evaluation 期间采用不同的行为。
- `optimizer.zero_grad()` 会在 backward pass 之前清除所有 optimized tensors 的 gradients，这是必要的，因为在 PyTorch 中 gradients 默认会累积。如果不清除，前一次迭代的 gradients 会被添加到当前 gradients 中，从而导致错误的更新。
- `loss.backward()` 会计算 loss 相对于 model parameters 的 gradients，随后 optimizer 会使用这些 gradients 更新 weights。
- `optimizer.step()` 会根据计算出的 gradients 和 learning rate 更新 model parameters。
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

Recurrent Neural Networks (RNNs) 是一类专为处理序列数据而设计的神经网络，例如时间序列或自然语言。与传统的前馈神经网络不同，RNNs 包含会回连自身的连接，使其能够维护一个隐藏状态，用于捕获序列中先前输入的信息。

RNNs 的主要组件包括：
- **Recurrent Layers**：这些层一次处理一个时间步的输入序列，并根据当前输入和之前的隐藏状态更新其隐藏状态。这使 RNNs 能够学习数据中的时间依赖关系。
- **Hidden State**：隐藏状态是一个总结之前时间步信息的向量。它会在每个时间步更新，并用于对当前输入进行预测。
- **Output Layer**：输出层根据隐藏状态生成最终预测。在许多情况下，RNNs 被用于 language modeling 等任务，其中输出是序列中下一个单词的概率分布。

例如，在 language model 中，RNN 会处理一个单词序列，例如 “The cat sat on the”，并根据前面单词提供的上下文预测下一个单词，在此例中为 “mat”。

### Long Short-Term Memory (LSTM) and Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

RNNs 对涉及序列数据的任务尤其有效，例如 language modeling、machine translation 和 speech recognition。然而，由于 **vanishing gradients 等问题，它们可能难以处理长程依赖关系**。

为了解决这一问题，研究人员开发了 Long Short-Term Memory (LSTM) 和 Gated Recurrent Unit (GRU) 等专用架构。这些架构引入了 gating mechanisms 来控制信息流，使其能够更有效地捕获长程依赖关系。

- **LSTM**：LSTM networks 使用三个 gates（input gate、forget gate 和 output gate）来调节信息进出 cell state 的流动，使其能够在较长序列中记住或遗忘信息。input gate 根据输入和之前的隐藏状态控制要添加多少新信息，forget gate 控制要丢弃多少信息。结合 input gate 和 forget gate 后，我们得到新的 state。最后，将新的 cell state、输入和之前的隐藏状态结合起来，即可得到新的 hidden state。
- **GRU**：GRU networks 通过将 input gate 和 forget gate 合并为单个 update gate，简化了 LSTM 架构，使其在仍能捕获长程依赖关系的同时，具备更高的 computational efficiency。

## LLMs (Large Language Models)

Large Language Models (LLMs) 是一种专门为 natural language processing 任务设计的 deep learning model。它们使用海量文本数据进行训练，能够生成类似人类的文本、回答问题、翻译语言，以及执行各种其他与语言相关的任务。
LLMs 通常基于 transformer architectures，使用 self-attention mechanisms 捕获序列中单词之间的关系，使其能够理解上下文并生成连贯的文本。

### Transformer Architecture <sup>[[4]](#references)</sup>
transformer architecture 是许多 LLMs 的基础。它由 encoder-decoder 结构组成，其中 encoder 处理输入序列，decoder 生成输出序列。transformer architecture 的关键组件包括：
- **Self-Attention Mechanism**：该机制允许模型在生成 representations 时评估序列中不同单词的重要性。它根据单词之间的关系计算 attention scores，使模型能够关注相关上下文。
- **Multi-Head Attention**：该组件通过使用多个 attention heads，使模型能够捕获单词之间的多种关系；每个 attention head 关注输入的不同方面。
- **Positional Encoding**：由于 transformers 没有内置的单词顺序概念，因此会将 positional encoding 添加到 input embeddings 中，以提供序列中单词位置的信息。

## Diffusion Models <sup>[[5]](#references)</sup>
Diffusion models 是一类通过模拟 diffusion process 来学习生成数据的 generative models。它们尤其适用于 image generation 等任务，并在近年来获得了广泛关注。
Diffusion models 通过一系列 diffusion steps，逐步将简单的 noise distribution 转换为复杂的 data distribution。Diffusion models 的关键组件包括：
- **Forward Diffusion Process**：该过程逐步向数据添加 noise，将其转换为简单的 noise distribution。Forward diffusion process 通常由一系列 noise levels 定义，其中每个 level 对应于向数据中添加的特定数量的 noise。
- **Reverse Diffusion Process**：该过程学习反转 forward diffusion process，通过逐步对数据进行 denoising，从 target distribution 生成 samples。Reverse diffusion process 使用 loss function 进行训练，该函数促使模型从 noisy samples 中重建原始数据。

此外，为了根据 text prompt 生成图像，diffusion models 通常遵循以下步骤：
1. **Text Encoding**：使用 text encoder（例如基于 transformer 的模型）将 text prompt 编码为 latent representation。该 representation 捕获文本的语义含义。
2. **Noise Sampling**：从 Gaussian distribution 中采样一个随机 noise vector。
3. **Diffusion Steps**：模型应用一系列 diffusion steps，逐步将 noise vector 转换为与 text prompt 对应的图像。每个步骤都涉及应用 learned transformations，对图像进行 denoising。

## References

- [1] [PyTorch - Neural Networks 教程](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [去噪扩散概率模型](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
