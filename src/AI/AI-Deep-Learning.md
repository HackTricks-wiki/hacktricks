# 딥 러닝

{{#include ../banners/hacktricks-training.md}}

## 딥 러닝 <sup>[[1]](#references)</sup>

딥 러닝은 데이터의 복잡한 패턴을 모델링하기 위해 여러 레이어로 구성된 neural network(심층 neural network)를 사용하는 machine learning의 하위 분야입니다. 딥 러닝은 computer vision, natural language processing, speech recognition을 비롯한 다양한 영역에서 뛰어난 성과를 거두었습니다.

### Neural Networks

Neural network는 딥 러닝의 구성 요소입니다. Neural network는 레이어로 구성된 상호 연결된 노드(뉴런)로 이루어집니다. 각 뉴런은 입력을 받고 가중 합을 적용한 다음, 그 결과를 activation function을 통과시켜 출력을 생성합니다. 레이어는 다음과 같이 분류할 수 있습니다.
- **Input Layer**: 입력 데이터를 받는 첫 번째 레이어입니다.
- **Hidden Layers**: 입력 데이터에 변환을 수행하는 중간 레이어입니다. Hidden Layer의 수와 각 레이어의 뉴런 수는 달라질 수 있으며, 이에 따라 서로 다른 아키텍처가 만들어집니다.
- **Output Layer**: classification 작업에서 class probability와 같은 network의 출력을 생성하는 마지막 레이어입니다.


### Activation Functions

뉴런 레이어가 입력 데이터를 처리할 때 각 뉴런은 입력에 weight와 bias를 적용합니다(`z = w * x + b`). 여기서 `w`는 weight, `x`는 입력, `b`는 bias입니다. 그런 다음 뉴런의 출력은 모델에 **비선형성을 도입하기 위한 activation function**을 통과합니다. 이 activation function은 기본적으로 다음 뉴런이 "활성화되어야 하는지, 그리고 어느 정도로 활성화되어야 하는지"를 나타냅니다. 이를 통해 network는 데이터의 복잡한 패턴과 관계를 학습할 수 있으며, 모든 연속 함수를 근사할 수 있습니다.

따라서 activation function은 neural network에 비선형성을 도입하여 데이터의 복잡한 관계를 학습할 수 있게 합니다. 일반적인 activation function은 다음과 같습니다.
- **Sigmoid**: 입력 값을 0에서 1 사이의 범위로 매핑하며, binary classification에서 자주 사용됩니다.
- **ReLU (Rectified Linear Unit)**: 입력 값이 양수이면 입력을 그대로 출력하고, 그렇지 않으면 0을 출력합니다. 단순하고 deep network의 training에 효과적이기 때문에 널리 사용됩니다.
- **Tanh**: 입력 값을 -1에서 1 사이의 범위로 매핑하며, hidden layer에서 자주 사용됩니다.
- **Softmax**: 원시 점수를 probability로 변환하며, multi-class classification에서 output layer에 자주 사용됩니다.

### Backpropagation

Backpropagation은 뉴런 사이 연결의 weight를 조정하여 neural network를 training하는 데 사용되는 알고리즘입니다. 이 알고리즘은 각 weight에 대한 loss function의 gradient를 계산하고, loss를 최소화하기 위해 gradient의 반대 방향으로 weight를 업데이트하는 방식으로 동작합니다. Backpropagation에 포함되는 단계는 다음과 같습니다.

1. **Forward Pass**: 입력을 레이어에 통과시키고 activation function을 적용하여 network의 출력을 계산합니다.
2. **Loss Calculation**: loss function(예: regression에서는 mean squared error, classification에서는 cross-entropy)을 사용하여 예측된 출력과 실제 target 사이의 loss(error)를 계산합니다.
3. **Backward Pass**: 미적분의 chain rule을 사용하여 각 weight에 대한 loss의 gradient를 계산합니다.
4. **Weight Update**: loss를 최소화하기 위해 optimization algorithm(예: stochastic gradient descent, Adam)을 사용하여 weight를 업데이트합니다.

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Convolutional Neural Networks (CNNs)는 이미지와 같은 격자 형태의 데이터를 처리하도록 설계된 특수한 유형의 neural network입니다. CNN은 feature의 spatial hierarchy를 자동으로 학습할 수 있기 때문에 computer vision 작업에 특히 효과적입니다.

CNN의 주요 구성 요소는 다음과 같습니다.
- **Convolutional Layers**: 학습 가능한 filter(kernel)를 사용하여 입력 데이터에 convolution 연산을 적용하고 local feature를 추출합니다. 각 filter는 입력 위를 이동하며 dot product를 계산하여 feature map을 생성합니다.
- **Pooling Layers**: 중요한 feature를 유지하면서 feature map의 spatial dimension을 줄이기 위해 downsample합니다. 일반적인 pooling 연산에는 max pooling과 average pooling이 있습니다.
- **Fully Connected Layers**: 전통적인 neural network와 마찬가지로 한 레이어의 모든 뉴런을 다음 레이어의 모든 뉴런에 연결합니다. 이러한 레이어는 일반적으로 classification 작업을 위해 network의 마지막 부분에서 사용됩니다.

CNN 내부의 **`Convolutional Layers`**는 다음과 같이 구분할 수도 있습니다.
- **Initial Convolutional Layer**: raw input data(예: 이미지)를 처리하는 첫 번째 convolutional layer이며, edge와 texture 같은 기본 feature를 식별하는 데 유용합니다.
- **Intermediate Convolutional Layers**: initial layer에서 학습한 feature를 기반으로 구축되는 후속 convolutional layer입니다. 이를 통해 network는 더 복잡한 패턴과 표현을 학습할 수 있습니다.
- **Final Convolutional Layer**: fully connected layer 이전의 마지막 convolutional layer로, high-level feature를 포착하고 classification을 위해 데이터를 준비합니다.

> [!TIP]
> CNNs는 격자 형태의 데이터에서 feature의 spatial hierarchy를 학습하고 weight sharing을 통해 parameter 수를 줄일 수 있기 때문에 image classification, object detection, image segmentation 작업에 특히 효과적입니다.
> 또한 feature locality principle을 지원하는 데이터에서 더 잘 작동합니다. 즉, 서로 인접한 데이터(픽셀)가 멀리 떨어진 픽셀보다 서로 관련되어 있을 가능성이 높다는 원칙입니다. 이는 text와 같은 다른 유형의 데이터에는 적용되지 않을 수 있습니다.
> 또한 CNNs는 복잡한 feature도 식별할 수 있지만 spatial context를 적용할 수는 없습니다. 즉, 이미지의 서로 다른 부분에서 발견된 동일한 feature는 동일하게 처리됩니다.

### CNN 정의 예시

*여기에서는 48x48 크기의 RGB image batch를 dataset으로 사용하고, convolutional layer와 maxpool을 통해 feature를 추출한 다음 classification을 위해 fully connected layer를 사용하는 PyTorch Convolutional Neural Network (CNN)의 정의 방법을 설명합니다.*

PyTorch에서 convolutional layer 1개는 다음과 같이 정의할 수 있습니다: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: 입력 channel의 수입니다. RGB image의 경우 각 color channel당 하나씩 총 3개입니다. grayscale image를 사용하는 경우에는 1이 됩니다.

- `out_channels`: convolutional layer가 학습할 출력 channel(filter)의 수입니다. 모델 아키텍처에 따라 조정할 수 있는 hyperparameter입니다.

- `kernel_size`: convolutional filter의 크기입니다. 일반적으로 3x3을 사용하며, 이는 filter가 입력 image의 3x3 영역을 덮는다는 의미입니다. 이는 `in_channels`에서 `out_channels`를 생성하는 데 사용되는 3×3×3 색상 도장과 같습니다.
1. 해당 3×3×3 도장을 image cube의 왼쪽 위 모서리에 놓습니다.
2. 각 weight에 그 아래의 픽셀 값을 곱하고 모두 더한 다음 bias를 더합니다 → 하나의 숫자를 얻습니다.
3. 해당 숫자를 빈 map의 (0, 0) 위치에 기록합니다.
4. 도장을 오른쪽으로 한 픽셀 이동합니다(stride = 1). 그런 다음 전체 48×48 grid를 채울 때까지 반복합니다.

- `padding`: 입력의 각 면에 추가되는 픽셀 수입니다. Padding은 입력의 spatial dimension을 유지하는 데 도움을 주므로 출력 크기를 더 세밀하게 제어할 수 있습니다. 예를 들어 3x3 kernel과 48x48 pixel 입력을 사용하는 경우 padding을 1로 설정하면 convolution 연산 후에도 출력 크기가 동일하게 유지됩니다(48x48). Padding이 입력 image 주변에 1픽셀의 border를 추가하여 kernel이 spatial dimension을 줄이지 않고 가장자리 위로 이동할 수 있도록 하기 때문입니다.

따라서 이 레이어의 trainable parameter 수는 다음과 같습니다.
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 trainable parameters.

각 convolutional layer의 기능은 입력의 linear transformation을 학습하는 것이며, 이는 다음 식으로 표현되므로 사용되는 각 kernel마다 Bias (+1)가 하나씩 추가된다는 점에 유의해야 합니다:
```plaintext
Y = f(W * X + b)
```
여기서 `W`는 weight matrix(학습된 filters, 3x3x3 = 27 params)이고, `b`는 각 output channel에 대해 +1인 bias vector입니다.

`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`의 output은 `(batch_size, 32, 48, 48)` 형태의 tensor가 됩니다. 32는 48x48 pixels 크기로 새롭게 생성된 channels의 수이기 때문입니다.

그런 다음 이 convolutional layer를 다음과 같이 또 다른 convolutional layer에 연결할 수 있습니다: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

이렇게 하면 (32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496개의 trainable parameters와 `(batch_size, 64, 48, 48)` 형태의 output이 추가됩니다.

보시다시피 **각 convolutional layer가 추가될 때마다 parameter의 수가 빠르게 증가**하며, 특히 output channels의 수가 증가할수록 더욱 그렇습니다.

사용되는 data의 양을 제어하는 한 가지 방법은 각 convolutional layer 뒤에 **max pooling**을 사용하는 것입니다. Max pooling은 feature maps의 spatial dimensions를 줄여 중요한 features를 유지하면서 parameters의 수와 computational complexity를 줄이는 데 도움을 줍니다.

다음과 같이 선언할 수 있습니다: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. 이는 기본적으로 2x2 pixels의 grid를 사용하고 각 grid에서 maximum value를 가져와 feature map의 크기를 절반으로 줄인다는 의미입니다. 또한 `stride=2`는 pooling operation이 한 번에 2 pixels씩 이동한다는 의미이며, 이 경우 pooling regions 간의 overlap을 방지합니다.

이 pooling layer를 사용하면 첫 번째 convolutional layer 이후의 output shape는 `self.conv2`의 output에 `self.pool1`을 적용한 뒤 `(batch_size, 64, 24, 24)`가 되며, 이전 layer 크기의 1/4로 줄어듭니다.

> [!TIP]
> feature maps의 spatial dimensions를 줄이기 위해 convolutional layers 뒤에 pooling을 적용하는 것이 중요합니다. 이는 parameters의 수와 computational complexity를 제어하는 데 도움이 되며, initial parameter가 중요한 features를 학습하도록 합니다.
>pooling layer 이전의 convolutions를 input data(예: lines, edges)에서 features를 추출하는 방법으로 볼 수 있습니다. 이 정보는 pooled output에도 여전히 존재하지만, 다음 convolutional layer는 원래의 input data를 볼 수 없고 해당 정보를 포함한 이전 layer의 축소된 버전인 pooled output만 볼 수 있습니다.
>일반적인 순서인 `Conv → ReLU → Pool`에서는 각 2×2 pooling window가 이제 raw pixel intensities가 아니라 feature activations(“edge present / not”)와 경쟁합니다. 가장 강한 activation을 유지하는 것은 실제로 가장 두드러진 evidence를 유지하는 것입니다.

그런 다음 필요한 만큼 convolutional 및 pooling layers를 추가한 뒤, output을 flatten하여 fully connected layers에 전달할 수 있습니다. 이는 batch의 각 sample에 대해 tensor를 1D vector로 reshape하여 수행합니다:
```python
x = x.view(-1, 64*24*24)
```
그리고 이전 convolutional 및 pooling layers에서 생성된 모든 training parameters를 포함하는 이 1D vector를 사용하여 다음과 같이 fully connected layer를 정의할 수 있습니다:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
이 계층은 이전 계층의 평탄화된 출력을 가져와 512개의 hidden units에 매핑합니다.

이 계층에서 `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504`개의 trainable parameters가 추가되었음을 확인할 수 있습니다. 이는 convolutional layers와 비교했을 때 상당히 큰 증가입니다. fully connected layers는 한 계층의 모든 뉴런을 다음 계층의 모든 뉴런에 연결하므로 많은 수의 parameters가 발생하기 때문입니다.

마지막으로 최종 class logits를 생성하는 output layer를 추가할 수 있습니다:
```python
self.fc2 = nn.Linear(512, num_classes)
```
이렇게 하면 `(512 + 1 (bias)) * num_classes`개의 학습 가능한 파라미터가 추가됩니다. 여기서 `num_classes`는 classification task의 클래스 수입니다(예: GTSRB dataset의 경우 43).

또 다른 일반적인 방법은 overfitting을 방지하기 위해 fully connected layers 앞에 dropout layer를 추가하는 것입니다. 다음과 같이 할 수 있습니다.
```python
self.dropout = nn.Dropout(0.5)
```
이 계층은 학습 중 입력 유닛의 일부를 무작위로 0으로 설정하여 특정 뉴런에 대한 의존도를 줄이고 overfitting을 방지하는 데 도움을 줍니다.

### CNN Code 예제
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

다음 코드는 일부 training data를 생성하고 위에서 정의한 `MY_NET` model을 train합니다. 다음과 같은 몇 가지 흥미로운 값을 확인할 수 있습니다.

- `EPOCHS`는 training 중 model이 전체 dataset을 확인하는 횟수입니다. EPOCH가 너무 작으면 model이 충분히 학습하지 못할 수 있으며, 너무 크면 overfit될 수 있습니다.
- `LEARNING_RATE`는 optimizer의 step size입니다. learning rate가 작으면 convergence가 느려질 수 있고, 크면 최적의 solution을 지나쳐 convergence를 방해할 수 있습니다.
- `WEIGHT_DECAY`는 큰 weight에 penalty를 적용하여 overfitting을 방지하는 데 도움이 되는 regularization term입니다.

training loop와 관련하여 알아두면 좋은 정보는 다음과 같습니다.
- `criterion = nn.CrossEntropyLoss()`는 multi-class classification task에 사용되는 loss function입니다. softmax activation과 cross-entropy loss를 하나의 function으로 결합하므로, class logits를 출력하는 model의 training에 적합합니다.
- model이 binary classification이나 regression처럼 다른 유형의 output을 출력해야 하는 경우에는 binary classification에 `nn.BCEWithLogitsLoss()`, regression에 `nn.MSELoss()`와 같은 다른 loss function을 사용합니다.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)`는 deep learning model training에 널리 사용되는 Adam optimizer를 초기화합니다. gradient의 first moment와 second moment를 기반으로 각 parameter의 learning rate를 조정합니다.
- training task의 구체적인 요구 사항에 따라 `optim.SGD` (Stochastic Gradient Descent) 또는 `optim.RMSprop`과 같은 다른 optimizer를 사용할 수도 있습니다.
- `model.train()` method는 model을 training mode로 설정하여 dropout 및 batch normalization과 같은 layer가 evaluation과 비교해 training 중 다르게 동작하도록 합니다.
- `optimizer.zero_grad()`는 backward pass 전에 모든 optimized tensor의 gradient를 지웁니다. PyTorch에서는 기본적으로 gradient가 누적되므로 이 과정이 필요합니다. 지우지 않으면 이전 iteration의 gradient가 현재 gradient에 더해져 잘못된 update가 발생합니다.
- `loss.backward()`는 model parameter에 대한 loss의 gradient를 계산하며, 이후 optimizer가 이 gradient를 사용하여 weight를 update합니다.
- `optimizer.step()`은 계산된 gradient와 learning rate를 기반으로 model parameter를 update합니다.
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
## 순환 신경망 (RNNs) <sup>[[3]](#references)</sup>

순환 신경망 (RNNs)은 시계열이나 자연어와 같은 순차 데이터를 처리하도록 설계된 신경망의 한 종류입니다. 기존의 feedforward neural networks와 달리 RNNs에는 자기 자신으로 되돌아가는 연결이 있어, 시퀀스의 이전 입력에 대한 정보를 캡처하는 hidden state를 유지할 수 있습니다.

RNNs의 주요 구성 요소는 다음과 같습니다.
- **Recurrent Layers**: 이 레이어는 입력 시퀀스를 한 번에 하나의 time step씩 처리하며, 현재 입력과 이전 hidden state를 기반으로 hidden state를 업데이트합니다. 이를 통해 RNNs는 데이터의 temporal dependencies를 학습할 수 있습니다.
- **Hidden State**: hidden state는 이전 time step의 정보를 요약하는 vector입니다. 각 time step에서 업데이트되며 현재 입력에 대한 prediction을 만드는 데 사용됩니다.
- **Output Layer**: output layer는 hidden state를 기반으로 최종 prediction을 생성합니다. 많은 경우 RNNs는 language modeling과 같은 작업에 사용되며, 이때 output은 시퀀스에서 다음 단어에 대한 probability distribution입니다.

예를 들어 language model에서 RNN은 단어 시퀀스, 예를 들어 "The cat sat on the"를 처리하고 이전 단어가 제공하는 context를 기반으로 다음 단어를 prediction합니다. 이 경우 다음 단어는 "mat"입니다.

### Long Short-Term Memory (LSTM) 및 Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

RNNs는 language modeling, machine translation, speech recognition과 같은 순차 데이터 관련 작업에 특히 효과적입니다. 그러나 **vanishing gradients와 같은 문제로 인해 long-range dependencies를 처리하는 데 어려움을 겪을 수 있습니다**.

이를 해결하기 위해 Long Short-Term Memory (LSTM) 및 Gated Recurrent Unit (GRU)과 같은 특수 아키텍처가 개발되었습니다. 이러한 아키텍처는 정보의 흐름을 제어하는 gating mechanisms를 도입하여 long-range dependencies를 더 효과적으로 캡처할 수 있도록 합니다.

- **LSTM**: LSTM networks는 세 가지 gate (input gate, forget gate, output gate)를 사용하여 cell state 안팎의 정보 흐름을 조절하므로, 긴 시퀀스에 걸쳐 정보를 기억하거나 잊을 수 있습니다. input gate는 input과 이전 hidden state를 기반으로 추가할 새로운 정보의 양을 제어하고, forget gate는 버릴 정보의 양을 제어합니다. input gate와 forget gate를 결합하면 새로운 state를 얻습니다. 마지막으로 새로운 cell state를 input 및 이전 hidden state와 결합하여 새로운 hidden state도 얻습니다.
- **GRU**: GRU networks는 input gate와 forget gate를 하나의 update gate로 결합하여 LSTM 아키텍처를 단순화합니다. 이를 통해 long-range dependencies를 계속 캡처하면서도 computational efficiency가 향상됩니다.

## LLMs (Large Language Models)

Large Language Models (LLMs)는 natural language processing 작업을 위해 특별히 설계된 deep learning model의 한 종류입니다. LLMs는 방대한 양의 text data로 학습되며, 사람과 유사한 text를 생성하고, 질문에 답변하고, 언어를 translation하며, 다양한 기타 language-related tasks를 수행할 수 있습니다.
LLMs는 일반적으로 transformer architectures를 기반으로 하며, self-attention mechanisms를 사용해 시퀀스 내 단어 간 관계를 캡처합니다. 이를 통해 context를 이해하고 일관성 있는 text를 생성할 수 있습니다.

### Transformer Architecture <sup>[[4]](#references)</sup>
transformer architecture는 많은 LLMs의 기반입니다. 이는 encoder-decoder structure로 구성되며, encoder는 input sequence를 처리하고 decoder는 output sequence를 생성합니다. transformer architecture의 주요 구성 요소는 다음과 같습니다.
- **Self-Attention Mechanism**: 이 mechanism은 model이 representations를 생성할 때 시퀀스 내 서로 다른 단어의 중요도에 가중치를 부여할 수 있도록 합니다. 단어 간 관계를 기반으로 attention scores를 계산하여 model이 관련 context에 집중할 수 있게 합니다.
- **Multi-Head Attention**: 이 component는 여러 attention heads를 사용하여 model이 단어 간 여러 관계를 캡처할 수 있도록 합니다. 각 head는 input의 서로 다른 측면에 집중합니다.
- **Positional Encoding**: transformers에는 word order에 대한 built-in 개념이 없으므로, 시퀀스에서 단어의 위치에 대한 정보를 제공하기 위해 positional encoding을 input embeddings에 추가합니다.

## Diffusion Models <sup>[[5]](#references)</sup>
Diffusion models는 diffusion process를 simulation하여 데이터를 생성하는 방법을 학습하는 generative models의 한 종류입니다. 특히 image generation과 같은 작업에 효과적이며 최근 몇 년 동안 인기를 얻었습니다.
Diffusion models는 일련의 diffusion steps를 통해 단순한 noise distribution을 복잡한 data distribution으로 점진적으로 변환하는 방식으로 작동합니다. Diffusion models의 주요 구성 요소는 다음과 같습니다.
- **Forward Diffusion Process**: 이 process는 data에 noise를 점진적으로 추가하여 단순한 noise distribution으로 변환합니다. Forward diffusion process는 일반적으로 일련의 noise levels로 정의되며, 각 level은 data에 추가되는 특정 noise의 양에 해당합니다.
- **Reverse Diffusion Process**: 이 process는 forward diffusion process를 reverse하여 data에서 점진적으로 noise를 제거하고 target distribution에서 samples를 생성하는 방법을 학습합니다. Reverse diffusion process는 noisy samples에서 original data를 reconstruct하도록 model을 유도하는 loss function을 사용하여 학습됩니다.

또한 text prompt에서 image를 생성하기 위해 diffusion models는 일반적으로 다음 단계를 따릅니다.
1. **Text Encoding**: text prompt는 text encoder (예: transformer-based model)를 사용하여 latent representation으로 encoding됩니다. 이 representation은 text의 semantic meaning을 캡처합니다.
2. **Noise Sampling**: Gaussian distribution에서 random noise vector를 sampling합니다.
3. **Diffusion Steps**: model은 일련의 diffusion steps를 적용하여 noise vector를 text prompt에 해당하는 image로 점진적으로 변환합니다. 각 step에서는 image에서 noise를 제거하기 위해 학습된 transformations를 적용합니다.

## References

- [1] [PyTorch - Neural Networks 튜토리얼](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Denoising Diffusion Probabilistic Models](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
