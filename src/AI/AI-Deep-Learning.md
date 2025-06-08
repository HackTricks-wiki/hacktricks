# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning

딥 러닝은 여러 층(딥 신경망)을 가진 신경망을 사용하여 데이터의 복잡한 패턴을 모델링하는 머신 러닝의 하위 집합입니다. 컴퓨터 비전, 자연어 처리 및 음성 인식 등 다양한 분야에서 놀라운 성공을 거두었습니다.

### Neural Networks

신경망은 딥 러닝의 기본 구성 요소입니다. 이들은 층으로 구성된 상호 연결된 노드(뉴런)로 이루어져 있습니다. 각 뉴런은 입력을 받고, 가중치 합을 적용한 후, 활성화 함수를 통해 결과를 출력으로 전달합니다. 층은 다음과 같이 분류할 수 있습니다:
- **Input Layer**: 입력 데이터를 받는 첫 번째 층.
- **Hidden Layers**: 입력 데이터에 변환을 수행하는 중간 층. 숨겨진 층과 각 층의 뉴런 수는 다양할 수 있으며, 이는 서로 다른 아키텍처로 이어집니다.
- **Output Layer**: 네트워크의 출력을 생성하는 최종 층으로, 분류 작업에서 클래스 확률과 같은 결과를 제공합니다.

### Activation Functions

뉴런의 층이 입력 데이터를 처리할 때, 각 뉴런은 입력에 가중치와 편향을 적용합니다(`z = w * x + b`), 여기서 `w`는 가중치, `x`는 입력, `b`는 편향입니다. 그런 다음 뉴런의 출력은 **모델에 비선형성을 도입하기 위해 활성화 함수**를 통과합니다. 이 활성화 함수는 다음 뉴런이 "활성화되어야 하는지와 얼마나"를 나타냅니다. 이를 통해 네트워크는 데이터의 복잡한 패턴과 관계를 학습할 수 있으며, 모든 연속 함수를 근사할 수 있습니다.

따라서 활성화 함수는 신경망에 비선형성을 도입하여 데이터의 복잡한 관계를 학습할 수 있게 합니다. 일반적인 활성화 함수는 다음과 같습니다:
- **Sigmoid**: 입력 값을 0과 1 사이의 범위로 매핑하며, 이진 분류에 자주 사용됩니다.
- **ReLU (Rectified Linear Unit)**: 입력이 양수일 경우 입력을 직접 출력하고, 그렇지 않으면 0을 출력합니다. 이는 단순성과 딥 네트워크 훈련의 효과성 덕분에 널리 사용됩니다.
- **Tanh**: 입력 값을 -1과 1 사이의 범위로 매핑하며, 주로 숨겨진 층에서 사용됩니다.
- **Softmax**: 원시 점수를 확률로 변환하며, 다중 클래스 분류를 위한 출력 층에서 자주 사용됩니다.

### Backpropagation

역전파는 뉴런 간의 연결 가중치를 조정하여 신경망을 훈련시키는 데 사용되는 알고리즘입니다. 이는 손실 함수의 기울기를 각 가중치에 대해 계산하고, 손실을 최소화하기 위해 기울기의 반대 방향으로 가중치를 업데이트하는 방식으로 작동합니다. 역전파에 포함된 단계는 다음과 같습니다:

1. **Forward Pass**: 입력을 층을 통해 전달하고 활성화 함수를 적용하여 네트워크의 출력을 계산합니다.
2. **Loss Calculation**: 예측된 출력과 실제 목표 간의 손실(오류)을 손실 함수(예: 회귀의 경우 평균 제곱 오차, 분류의 경우 교차 엔트로피)를 사용하여 계산합니다.
3. **Backward Pass**: 미분 법칙을 사용하여 각 가중치에 대한 손실의 기울기를 계산합니다.
4. **Weight Update**: 손실을 최소화하기 위해 최적화 알고리즘(예: 확률적 경량 하강법, Adam)을 사용하여 가중치를 업데이트합니다.

## Convolutional Neural Networks (CNNs)

합성곱 신경망(CNN)은 이미지와 같은 격자 형태의 데이터를 처리하기 위해 설계된 특수한 유형의 신경망입니다. 이들은 공간적 특징의 계층 구조를 자동으로 학습할 수 있는 능력 덕분에 컴퓨터 비전 작업에서 특히 효과적입니다.

CNN의 주요 구성 요소는 다음과 같습니다:
- **Convolutional Layers**: 입력 데이터에 대해 학습 가능한 필터(커널)를 사용하여 합성곱 연산을 적용하여 지역 특징을 추출합니다. 각 필터는 입력 위를 슬라이드하며 점곱을 계산하여 특징 맵을 생성합니다.
- **Pooling Layers**: 중요한 특징을 유지하면서 특징 맵의 공간 차원을 줄입니다. 일반적인 풀링 연산에는 최대 풀링과 평균 풀링이 포함됩니다.
- **Fully Connected Layers**: 한 층의 모든 뉴런을 다음 층의 모든 뉴런에 연결하며, 전통적인 신경망과 유사합니다. 이러한 층은 일반적으로 분류 작업을 위해 네트워크의 끝에서 사용됩니다.

CNN의 **`Convolutional Layers`** 내부에서는 다음과 같은 구분도 가능합니다:
- **Initial Convolutional Layer**: 원시 입력 데이터(예: 이미지)를 처리하는 첫 번째 합성곱 층으로, 엣지 및 텍스처와 같은 기본 특징을 식별하는 데 유용합니다.
- **Intermediate Convolutional Layers**: 초기 층에서 학습한 특징을 기반으로 구축된 후속 합성곱 층으로, 네트워크가 더 복잡한 패턴과 표현을 학습할 수 있게 합니다.
- **Final Convolutional Layer**: 완전 연결 층 이전의 마지막 합성곱 층으로, 고수준의 특징을 캡처하고 분류를 위해 데이터를 준비합니다.

> [!TIP]
> CNN은 격자 형태의 데이터에서 특징의 공간적 계층 구조를 학습하고 가중치 공유를 통해 매개변수 수를 줄일 수 있는 능력 덕분에 이미지 분류, 객체 탐지 및 이미지 분할 작업에 특히 효과적입니다.
> 또한, 이들은 이웃 데이터(픽셀)가 먼 픽셀보다 더 관련성이 높을 가능성이 있는 특징 지역성 원칙을 지원하는 데이터에서 더 잘 작동합니다. 이는 텍스트와 같은 다른 유형의 데이터에서는 해당되지 않을 수 있습니다.
> 또한, CNN이 복잡한 특징을 식별할 수 있지만 공간적 맥락을 적용할 수 없다는 점에 유의하십시오. 즉, 이미지의 서로 다른 부분에서 발견된 동일한 특징은 동일할 것입니다.

### Example defining a CNN

*여기에서는 48x48 크기의 RGB 이미지 배치를 데이터셋으로 사용하고, 특징을 추출하기 위해 합성곱 층과 최대 풀링을 사용하며, 분류를 위해 완전 연결 층을 사용하는 합성곱 신경망(CNN)을 정의하는 방법에 대한 설명을 찾을 수 있습니다.*

다음은 PyTorch에서 1개의 합성곱 층을 정의하는 방법입니다: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: 입력 채널 수. RGB 이미지의 경우, 이는 3(각 색상 채널마다 하나)입니다. 그레이스케일 이미지의 경우, 이는 1이 됩니다.

- `out_channels`: 합성곱 층이 학습할 출력 채널(필터) 수입니다. 이는 모델 아키텍처에 따라 조정할 수 있는 하이퍼파라미터입니다.

- `kernel_size`: 합성곱 필터의 크기입니다. 일반적인 선택은 3x3이며, 이는 필터가 입력 이미지의 3x3 영역을 커버함을 의미합니다. 이는 in_channels에서 out_channels를 생성하는 데 사용되는 3×3×3 색상 스탬프와 같습니다:
1. 그 3×3×3 스탬프를 이미지 큐브의 왼쪽 상단 모서리에 놓습니다.
2. 각 가중치를 그 아래의 픽셀에 곱하고 모두 더한 후, 편향을 추가하여 하나의 숫자를 얻습니다.
3. 그 숫자를 빈 맵의 위치(0, 0)에 기록합니다.
4. 스탬프를 오른쪽으로 한 픽셀 슬라이드(스트라이드 = 1)하고 전체 48×48 그리드를 채울 때까지 반복합니다.

- `padding`: 입력의 각 측면에 추가되는 픽셀 수입니다. 패딩은 입력의 공간 차원을 보존하는 데 도움이 되어 출력 크기를 더 잘 제어할 수 있게 합니다. 예를 들어, 3x3 커널을 가진 48x48 픽셀 입력의 경우, 패딩 1은 합성곱 연산 후 출력 크기를 동일하게 유지합니다(48x48). 이는 패딩이 입력 이미지 주위에 1픽셀의 경계를 추가하여 커널이 가장자리를 슬라이드할 수 있게 하여 공간 차원을 줄이지 않도록 합니다.

그런 다음 이 층의 학습 가능한 매개변수 수는 다음과 같습니다:
- (3x3x3 (커널 크기) + 1 (편향)) x 32 (out_channels) = 896 학습 가능한 매개변수.

각 합성곱 층의 기능은 입력의 선형 변환을 학습하는 것이므로 사용된 각 커널마다 편향(+1)이 추가됩니다. 이는 다음과 같은 방정식으로 표현됩니다:
```plaintext
Y = f(W * X + b)
```
`W`는 가중치 행렬(학습된 필터, 3x3x3 = 27개의 매개변수)이고, `b`는 각 출력 채널에 대해 +1인 바이어스 벡터입니다.

`self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`의 출력은 `(batch_size, 32, 48, 48)` 형태의 텐서가 될 것입니다. 여기서 32는 48x48 픽셀 크기의 새로 생성된 채널 수입니다.

그런 다음, 이 합성곱 층을 다른 합성곱 층에 연결할 수 있습니다: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

이것은 다음을 추가합니다: (32x3x3 (커널 크기) + 1 (바이어스)) x 64 (출력 채널) = 18,496개의 학습 가능한 매개변수와 `(batch_size, 64, 48, 48)` 형태의 출력을 생성합니다.

보시다시피 **매개변수의 수는 각 추가 합성곱 층과 함께 빠르게 증가합니다**, 특히 출력 채널 수가 증가함에 따라.

데이터 사용량을 제어하는 한 가지 옵션은 각 합성곱 층 뒤에 **최대 풀링**을 사용하는 것입니다. 최대 풀링은 특징 맵의 공간 차원을 줄여 매개변수 수와 계산 복잡성을 줄이는 데 도움이 되며 중요한 특징을 유지합니다.

다음과 같이 선언할 수 있습니다: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. 이는 기본적으로 2x2 픽셀 그리드를 사용하고 각 그리드에서 최대 값을 취해 특징 맵의 크기를 절반으로 줄이는 것을 나타냅니다. 또한, `stride=2`는 풀링 작업이 한 번에 2픽셀씩 이동함을 의미하며, 이 경우 풀링 영역 간의 겹침을 방지합니다.

이 풀링 층을 사용하면 첫 번째 합성곱 층 이후의 출력 형태는 `self.conv2`의 출력에 `self.pool1`을 적용한 후 `(batch_size, 64, 24, 24)`가 되어 이전 층의 크기를 1/4로 줄입니다.

> [!TIP]
> 합성곱 층 뒤에 풀링을 하는 것이 중요합니다. 이는 특징 맵의 공간 차원을 줄여 매개변수 수와 계산 복잡성을 제어하는 데 도움이 되며, 초기 매개변수가 중요한 특징을 학습하도록 합니다.
> 풀링 층 앞의 합성곱을 입력 데이터에서 특징을 추출하는 방법으로 볼 수 있습니다(예: 선, 모서리). 이 정보는 여전히 풀링된 출력에 존재하지만, 다음 합성곱 층은 원래 입력 데이터를 볼 수 없고, 오직 풀링된 출력만 볼 수 있습니다. 이는 이전 층의 정보가 축소된 버전입니다.
> 일반적인 순서: `Conv → ReLU → Pool`에서 각 2×2 풀링 창은 이제 특징 활성화(“모서리 존재 / 없음”)와 경쟁하며, 원시 픽셀 강도와는 다릅니다. 가장 강한 활성화를 유지하는 것은 정말로 가장 두드러진 증거를 유지합니다.

그런 다음 필요한 만큼의 합성곱 및 풀링 층을 추가한 후, 출력을 평탄화하여 완전 연결 층에 공급할 수 있습니다. 이는 배치의 각 샘플에 대해 텐서를 1D 벡터로 재구성하여 수행됩니다:
```python
x = x.view(-1, 64*24*24)
```
그리고 이전의 합성곱 및 풀링 레이어에서 생성된 모든 훈련 매개변수를 가진 이 1D 벡터로, 다음과 같이 완전 연결 레이어를 정의할 수 있습니다:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
이 레이어는 이전 레이어의 평탄화된 출력을 가져와 512개의 숨겨진 유닛에 매핑합니다.

이 레이어가 추가한 `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` 개의 학습 가능한 매개변수를 주목하세요. 이는 합성곱 레이어에 비해 상당한 증가입니다. 이는 완전 연결 레이어가 한 레이어의 모든 뉴런을 다음 레이어의 모든 뉴런에 연결하기 때문에 매개변수의 수가 많아집니다.

마지막으로, 최종 클래스 로짓을 생성하기 위해 출력 레이어를 추가할 수 있습니다:
```python
self.fc2 = nn.Linear(512, num_classes)
```
이것은 `(512 + 1 (bias)) * num_classes`의 학습 가능한 매개변수를 추가합니다. 여기서 `num_classes`는 분류 작업의 클래스 수입니다 (예: GTSRB 데이터셋의 경우 43).

또 다른 일반적인 관행은 과적합을 방지하기 위해 완전 연결 계층 전에 드롭아웃 레이어를 추가하는 것입니다. 이는 다음과 같이 수행할 수 있습니다:
```python
self.dropout = nn.Dropout(0.5)
```
이 레이어는 훈련 중 입력 유닛의 일부를 무작위로 0으로 설정하여 특정 뉴런에 대한 의존도를 줄임으로써 과적합을 방지하는 데 도움을 줍니다.

### CNN 코드 예제
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
### CNN 코드 훈련 예제

다음 코드는 일부 훈련 데이터를 생성하고 위에서 정의한 `MY_NET` 모델을 훈련합니다. 주목할 만한 몇 가지 흥미로운 값은 다음과 같습니다:

- `EPOCHS`는 모델이 훈련 중 전체 데이터셋을 보는 횟수입니다. EPOCH이 너무 작으면 모델이 충분히 학습하지 못할 수 있고, 너무 크면 과적합될 수 있습니다.
- `LEARNING_RATE`는 최적화기의 단계 크기입니다. 작은 학습률은 느린 수렴으로 이어질 수 있고, 큰 학습률은 최적 솔루션을 초과하여 수렴을 방해할 수 있습니다.
- `WEIGHT_DECAY`는 큰 가중치에 대해 패널티를 부여하여 과적합을 방지하는 정규화 항입니다.

훈련 루프와 관련하여 알아두면 좋은 흥미로운 정보는 다음과 같습니다:
- `criterion = nn.CrossEntropyLoss()`는 다중 클래스 분류 작업에 사용되는 손실 함수입니다. 소프트맥스 활성화와 교차 엔트로피 손실을 단일 함수로 결합하여 클래스 로짓을 출력하는 모델 훈련에 적합합니다.
- 모델이 이진 분류나 회귀와 같은 다른 유형의 출력을 예상하는 경우, 이진 분류에는 `nn.BCEWithLogitsLoss()`, 회귀에는 `nn.MSELoss()`와 같은 다른 손실 함수를 사용합니다.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)`는 딥 러닝 모델 훈련에 인기 있는 선택인 Adam 최적화를 초기화합니다. 이는 기울기의 첫 번째 및 두 번째 모멘트를 기반으로 각 매개변수에 대한 학습률을 조정합니다.
- `optim.SGD` (확률적 경사 하강법) 또는 `optim.RMSprop`와 같은 다른 최적화기도 훈련 작업의 특정 요구 사항에 따라 사용할 수 있습니다.
- `model.train()` 메서드는 모델을 훈련 모드로 설정하여 드롭아웃 및 배치 정규화와 같은 레이어가 평가와 비교하여 훈련 중에 다르게 동작하도록 합니다.
- `optimizer.zero_grad()`는 역전파 이전에 모든 최적화된 텐서의 기울기를 지웁니다. 이는 PyTorch에서 기울기가 기본적으로 누적되기 때문에 필요합니다. 지우지 않으면 이전 반복의 기울기가 현재 기울기에 추가되어 잘못된 업데이트가 발생할 수 있습니다.
- `loss.backward()`는 모델 매개변수에 대한 손실의 기울기를 계산하며, 이는 이후 최적화기가 가중치를 업데이트하는 데 사용됩니다.
- `optimizer.step()`은 계산된 기울기와 학습률에 따라 모델 매개변수를 업데이트합니다.
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
## 순환 신경망 (RNNs)

순환 신경망 (RNNs)은 시계열 데이터나 자연어와 같은 순차적 데이터를 처리하기 위해 설계된 신경망의 한 종류입니다. 전통적인 피드포워드 신경망과 달리, RNNs는 자신에게 다시 연결되는 연결을 가지고 있어, 시퀀스의 이전 입력에 대한 정보를 캡처하는 숨겨진 상태를 유지할 수 있습니다.

RNNs의 주요 구성 요소는 다음과 같습니다:
- **순환 레이어**: 이 레이어는 입력 시퀀스를 한 번에 한 시간 단계씩 처리하며, 현재 입력과 이전 숨겨진 상태에 따라 숨겨진 상태를 업데이트합니다. 이를 통해 RNNs는 데이터의 시간적 의존성을 학습할 수 있습니다.
- **숨겨진 상태**: 숨겨진 상태는 이전 시간 단계의 정보를 요약한 벡터입니다. 각 시간 단계에서 업데이트되며, 현재 입력에 대한 예측을 만드는 데 사용됩니다.
- **출력 레이어**: 출력 레이어는 숨겨진 상태를 기반으로 최종 예측을 생성합니다. 많은 경우, RNNs는 언어 모델링과 같은 작업에 사용되며, 이 경우 출력은 시퀀스의 다음 단어에 대한 확률 분포입니다.

예를 들어, 언어 모델에서 RNN은 "The cat sat on the"와 같은 단어 시퀀스를 처리하고, 이전 단어들이 제공하는 맥락에 따라 다음 단어를 예측합니다. 이 경우 "mat"입니다.

### 장기 단기 기억 (LSTM) 및 게이티드 순환 유닛 (GRU)

RNNs는 언어 모델링, 기계 번역 및 음성 인식과 같은 순차적 데이터와 관련된 작업에 특히 효과적입니다. 그러나 **소실 기울기**와 같은 문제로 인해 **장기 의존성**을 처리하는 데 어려움을 겪을 수 있습니다.

이를 해결하기 위해 장기 단기 기억 (LSTM) 및 게이티드 순환 유닛 (GRU)과 같은 특수 아키텍처가 개발되었습니다. 이러한 아키텍처는 정보를 흐르게 하는 게이팅 메커니즘을 도입하여 장기 의존성을 보다 효과적으로 캡처할 수 있게 합니다.

- **LSTM**: LSTM 네트워크는 셀 상태의 정보 흐름을 조절하기 위해 세 개의 게이트(입력 게이트, 망각 게이트 및 출력 게이트)를 사용하여 긴 시퀀스에서 정보를 기억하거나 잊을 수 있게 합니다. 입력 게이트는 입력과 이전 숨겨진 상태에 따라 얼마나 많은 새로운 정보를 추가할지를 조절하고, 망각 게이트는 얼마나 많은 정보를 버릴지를 조절합니다. 입력 게이트와 망각 게이트를 결합하여 새로운 상태를 얻습니다. 마지막으로, 새로운 셀 상태와 입력 및 이전 숨겨진 상태를 결합하여 새로운 숨겨진 상태를 얻습니다.
- **GRU**: GRU 네트워크는 입력 게이트와 망각 게이트를 단일 업데이트 게이트로 결합하여 LSTM 아키텍처를 단순화하여 계산적으로 더 효율적이면서도 여전히 장기 의존성을 캡처할 수 있게 합니다.

## LLMs (대형 언어 모델)

대형 언어 모델 (LLMs)은 자연어 처리 작업을 위해 특별히 설계된 딥 러닝 모델의 한 종류입니다. 이들은 방대한 양의 텍스트 데이터로 훈련되어 인간과 유사한 텍스트를 생성하고, 질문에 답하고, 언어를 번역하며, 다양한 언어 관련 작업을 수행할 수 있습니다.
LLMs는 일반적으로 변환기 아키텍처를 기반으로 하며, 이는 시퀀스 내 단어 간의 관계를 캡처하기 위해 자기 주의 메커니즘을 사용하여 맥락을 이해하고 일관된 텍스트를 생성할 수 있게 합니다.

### 변환기 아키텍처
변환기 아키텍처는 많은 LLMs의 기초입니다. 이는 인코더-디코더 구조로 구성되어 있으며, 인코더는 입력 시퀀스를 처리하고 디코더는 출력 시퀀스를 생성합니다. 변환기 아키텍처의 주요 구성 요소는 다음과 같습니다:
- **자기 주의 메커니즘**: 이 메커니즘은 모델이 표현을 생성할 때 시퀀스 내의 다양한 단어의 중요성을 가중치로 부여할 수 있게 합니다. 이는 단어 간의 관계를 기반으로 주의 점수를 계산하여 모델이 관련 맥락에 집중할 수 있게 합니다.
- **다중 헤드 주의**: 이 구성 요소는 모델이 여러 주의 헤드를 사용하여 단어 간의 여러 관계를 캡처할 수 있게 하며, 각 헤드는 입력의 다양한 측면에 집중합니다.
- **위치 인코딩**: 변환기는 단어 순서에 대한 내장 개념이 없기 때문에, 위치 인코딩이 입력 임베딩에 추가되어 시퀀스 내 단어의 위치에 대한 정보를 제공합니다.

## 확산 모델
확산 모델은 확산 과정을 시뮬레이션하여 데이터를 생성하는 방법을 학습하는 생성 모델의 한 종류입니다. 이들은 이미지 생성과 같은 작업에 특히 효과적이며 최근 몇 년 동안 인기를 얻고 있습니다.
확산 모델은 간단한 노이즈 분포를 복잡한 데이터 분포로 점진적으로 변환하는 방식으로 작동합니다. 확산 모델의 주요 구성 요소는 다음과 같습니다:
- **정방향 확산 과정**: 이 과정은 데이터를 점진적으로 노이즈를 추가하여 간단한 노이즈 분포로 변환합니다. 정방향 확산 과정은 일반적으로 각 수준이 데이터에 추가된 특정 양의 노이즈에 해당하는 일련의 노이즈 수준으로 정의됩니다.
- **역방향 확산 과정**: 이 과정은 정방향 확산 과정을 역전시키는 방법을 학습하여 데이터를 점진적으로 디노이즈하여 목표 분포에서 샘플을 생성합니다. 역방향 확산 과정은 모델이 노이즈 샘플에서 원래 데이터를 재구성하도록 유도하는 손실 함수를 사용하여 훈련됩니다.

또한, 텍스트 프롬프트에서 이미지를 생성하기 위해 확산 모델은 일반적으로 다음 단계를 따릅니다:
1. **텍스트 인코딩**: 텍스트 프롬프트는 텍스트 인코더(예: 변환기 기반 모델)를 사용하여 잠재 표현으로 인코딩됩니다. 이 표현은 텍스트의 의미를 캡처합니다.
2. **노이즈 샘플링**: 가우시안 분포에서 무작위 노이즈 벡터가 샘플링됩니다.
3. **확산 단계**: 모델은 일련의 확산 단계를 적용하여 노이즈 벡터를 텍스트 프롬프트에 해당하는 이미지로 점진적으로 변환합니다. 각 단계는 이미지를 디노이즈하기 위해 학습된 변환을 적용하는 것을 포함합니다.


{{#include ../banners/hacktricks-training.md}}
