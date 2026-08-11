# डीप Learning

{{#include ../banners/hacktricks-training.md}}

## डीप Learning <sup>[[1]](#references)</sup>

डीप Learning, machine learning का एक subset है, जो data में complex patterns को model करने के लिए multiple layers वाले neural networks (deep neural networks) का उपयोग करता है। इसने computer vision, natural language processing और speech recognition सहित विभिन्न domains में उल्लेखनीय सफलता प्राप्त की है।

### Neural Networks

Neural networks, deep learning के building blocks हैं। इनमें layers में व्यवस्थित interconnected nodes (neurons) होते हैं। प्रत्येक neuron inputs प्राप्त करता है, weighted sum लागू करता है और output उत्पन्न करने के लिए परिणाम को activation function के माध्यम से भेजता है। Layers को इस प्रकार वर्गीकृत किया जा सकता है:
- **Input Layer**: पहली layer, जो input data प्राप्त करती है।
- **Hidden Layers**: Intermediate layers, जो input data पर transformations करती हैं। Hidden layers की संख्या और प्रत्येक layer में neurons की संख्या अलग-अलग हो सकती है, जिससे विभिन्न architectures बनते हैं।
- **Output Layer**: अंतिम layer, जो network का output उत्पन्न करती है, जैसे classification tasks में class probabilities।


### Activation Functions

जब neurons की कोई layer input data को process करती है, तो प्रत्येक neuron input पर एक weight और bias लागू करता है (`z = w * x + b`), जहाँ `w` weight है, `x` input है और `b` bias है। इसके बाद neuron का output model में **non-linearity शामिल करने के लिए activation function के माध्यम से भेजा जाता है**। यह activation function मूल रूप से बताता है कि अगला neuron "activate होना चाहिए या नहीं और कितना"। इससे network data में complex patterns और relationships सीख सकता है तथा किसी भी continuous function का approximation कर सकता है।

इसलिए, activation functions neural network में non-linearity शामिल करते हैं, जिससे वह data में complex relationships सीख सकता है। सामान्य activation functions में शामिल हैं:
- **Sigmoid**: Input values को 0 और 1 के बीच की range में map करता है; आमतौर पर binary classification में उपयोग किया जाता है।
- **ReLU (Rectified Linear Unit)**: यदि input positive हो तो उसे सीधे output करता है; अन्यथा zero output करता है। Deep networks की training में इसकी simplicity और effectiveness के कारण इसका व्यापक रूप से उपयोग किया जाता है।
- **Tanh**: Input values को -1 और 1 के बीच की range में map करता है; आमतौर पर hidden layers में उपयोग किया जाता है।
- **Softmax**: Raw scores को probabilities में convert करता है; आमतौर पर multi-class classification के लिए output layer में उपयोग किया जाता है।

### Backpropagation

Backpropagation, neural networks को train करने के लिए उपयोग किया जाने वाला algorithm है, जो neurons के बीच connections के weights को adjust करता है। यह प्रत्येक weight के संबंध में loss function के gradient की गणना करके और loss को minimize करने के लिए weights को gradient की विपरीत दिशा में update करके काम करता है। Backpropagation में शामिल steps हैं:

1. **Forward Pass**: Input को layers के माध्यम से पास करके और activation functions लागू करके network का output compute करें।
2. **Loss Calculation**: Loss function का उपयोग करके predicted output और true target के बीच loss (error) calculate करें (जैसे regression के लिए mean squared error और classification के लिए cross-entropy)।
3. **Backward Pass**: Calculus के chain rule का उपयोग करके प्रत्येक weight के संबंध में loss के gradients compute करें।
4. **Weight Update**: Loss को minimize करने के लिए optimization algorithm (जैसे stochastic gradient descent और Adam) का उपयोग करके weights update करें।

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Convolutional Neural Networks (CNNs), grid-like data, जैसे images, को process करने के लिए designed neural network का एक specialized प्रकार हैं। Spatial hierarchies of features को automatically learn करने की क्षमता के कारण ये computer vision tasks में विशेष रूप से effective हैं।

CNNs के मुख्य components में शामिल हैं:
- **Convolutional Layers**: Local features extract करने के लिए learnable filters (kernels) का उपयोग करके input data पर convolution operations लागू करती हैं। प्रत्येक filter input पर slide करता है और dot product compute करता है, जिससे एक feature map उत्पन्न होता है।
- **Pooling Layers**: Important features को बनाए रखते हुए उनके spatial dimensions को कम करने के लिए feature maps को downsample करती हैं। सामान्य pooling operations में max pooling और average pooling शामिल हैं।
- **Fully Connected Layers**: एक layer के प्रत्येक neuron को अगली layer के प्रत्येक neuron से connect करती हैं, जैसा कि traditional neural networks में होता है। Classification tasks के लिए इन layers का उपयोग आमतौर पर network के अंत में किया जाता है।

एक CNN की **`Convolutional Layers`** के अंदर, हम इनके बीच भी अंतर कर सकते हैं:
- **Initial Convolutional Layer**: पहली convolutional layer, जो raw input data (जैसे image) को process करती है और edges तथा textures जैसे basic features की पहचान करने में उपयोगी होती है।
- **Intermediate Convolutional Layers**: Subsequent convolutional layers, जो initial layer द्वारा सीखे गए features पर build करती हैं और network को अधिक complex patterns तथा representations सीखने देती हैं।
- **Final Convolutional Layer**: Fully connected layers से पहले की अंतिम convolutional layers, जो high-level features capture करती हैं और data को classification के लिए तैयार करती हैं।

> [!TIP]
> Grid-like data में features की spatial hierarchies सीखने और weight sharing के माध्यम से parameters की संख्या कम करने की क्षमता के कारण CNNs image classification, object detection और image segmentation tasks के लिए विशेष रूप से effective हैं।
> इसके अलावा, वे feature locality principle को support करने वाले data के साथ बेहतर काम करते हैं, जहाँ neighboring data (pixels) के distant pixels की तुलना में related होने की अधिक संभावना होती है। Text जैसे अन्य प्रकार के data के लिए ऐसा आवश्यक नहीं है।
> यह भी ध्यान दें कि CNNs complex features की पहचान करने में सक्षम होंगे, लेकिन किसी spatial context को लागू नहीं कर पाएँगे। इसका अर्थ है कि image के अलग-अलग हिस्सों में पाया जाने वाला समान feature एक जैसा ही होगा।

### CNN define करने का Example

*यहाँ आपको PyTorch में Convolutional Neural Network (CNN) define करने का विवरण मिलेगा, जो dataset के रूप में 48x48 आकार वाली RGB images के batch से शुरू होता है और features extract करने के लिए convolutional layers तथा maxpool का उपयोग करता है, जिसके बाद classification के लिए fully connected layers होती हैं।*

PyTorch में 1 convolutional layer को इस प्रकार define किया जा सकता है: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`।

- `in_channels`: Input channels की संख्या। RGB images के मामले में यह 3 होती है (प्रत्येक color channel के लिए एक)। यदि आप grayscale images के साथ काम कर रहे हैं, तो यह 1 होगी।

- `out_channels`: Output channels (filters) की संख्या, जिन्हें convolutional layer learn करेगी। यह एक hyperparameter है, जिसे आप अपने model architecture के आधार पर adjust कर सकते हैं।

- `kernel_size`: Convolutional filter का आकार। सामान्य विकल्प 3x3 है, जिसका अर्थ है कि filter input image के 3x3 क्षेत्र को cover करेगा। यह एक 3×3×3 colour stamp की तरह है, जिसका उपयोग `out_channels` को `in_channels` से generate करने के लिए किया जाता है:
1. उस 3×3×3 stamp को image cube के top-left corner पर रखें।
2. प्रत्येक weight को उसके नीचे मौजूद pixel से multiply करें, सभी को जोड़ें, bias जोड़ें → आपको एक number प्राप्त होगा।
3. उस number को position (0, 0) पर मौजूद blank map में लिखें।
4. Stamp को एक pixel दाईं ओर slide करें (stride = 1) और तब तक दोहराएँ, जब तक पूरा 48×48 grid fill न हो जाए।

- `padding`: Input की प्रत्येक side पर जोड़े गए pixels की संख्या। Padding input के spatial dimensions को preserve करने में सहायता करता है और output size पर अधिक control देता है। उदाहरण के लिए, 3x3 kernel और 48x48 pixel input के साथ, padding का मान 1 होने पर convolution operation के बाद output size समान (48x48) रहेगा। ऐसा इसलिए है क्योंकि padding input image के चारों ओर 1 pixel का border जोड़ता है, जिससे kernel spatial dimensions को कम किए बिना edges पर slide कर सकता है।

इस layer में trainable parameters की संख्या है:
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 trainable parameters।

ध्यान दें कि उपयोग किए गए प्रत्येक kernel के लिए एक Bias (+1) जोड़ा जाता है, क्योंकि प्रत्येक convolutional layer का function input का linear transformation सीखना है, जिसे निम्न equation द्वारा दर्शाया जाता है:
```plaintext
Y = f(W * X + b)
```
जहाँ `W` weight matrix (सीखे गए filters, 3x3x3 = 27 params) है, `b` bias vector है, जो प्रत्येक output channel के लिए +1 होता है।

ध्यान दें कि `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` का output `(batch_size, 32, 48, 48)` shape वाला tensor होगा, क्योंकि 32, 48x48 pixels के आकार वाले नए generated channels की संख्या है।

इसके बाद, हम इस convolutional layer को किसी अन्य convolutional layer से इस प्रकार connect कर सकते हैं: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`।

यह जोड़ेगा: (32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 trainable parameters और `(batch_size, 64, 48, 48)` shape का output देगा।

जैसा कि आप देख सकते हैं, **प्रत्येक अतिरिक्त convolutional layer के साथ parameters की संख्या तेज़ी से बढ़ती है**, विशेष रूप से तब, जब output channels की संख्या बढ़ती है।

उपयोग किए जाने वाले data की मात्रा को नियंत्रित करने का एक विकल्प प्रत्येक convolutional layer के बाद **max pooling** का उपयोग करना है। Max pooling feature maps के spatial dimensions को कम करता है, जिससे महत्वपूर्ण features को बनाए रखते हुए parameters की संख्या और computational complexity कम करने में सहायता मिलती है।

इसे इस प्रकार declare किया जा सकता है: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`। इसका मूल अर्थ 2x2 pixels के grid का उपयोग करना और feature map का आकार आधा करने के लिए प्रत्येक grid से maximum value लेना है। इसके अलावा, `stride=2` का अर्थ है कि pooling operation एक बार में 2 pixels आगे बढ़ेगा; इस मामले में, pooling regions के बीच किसी भी overlap को रोका जाता है।

इस pooling layer के साथ, पहले convolutional layer के बाद output shape `(batch_size, 64, 24, 24)` होगा, जब `self.pool1` को `self.conv2` के output पर लागू किया जाएगा और आकार को पिछली layer के 1/4 तक कम किया जाएगा।

> [!TIP]
> Feature maps के spatial dimensions को कम करने के लिए convolutional layers के बाद pooling करना महत्वपूर्ण है। इससे parameters की संख्या और computational complexity को नियंत्रित करने में सहायता मिलती है, साथ ही initial parameter को महत्वपूर्ण features सीखने में सक्षम बनाया जाता है।
>आप convolutional layers को pooling layer से पहले input data (जैसे lines, edges) से features extract करने के तरीके के रूप में देख सकते हैं। यह information pooled output में अभी भी मौजूद रहेगी, लेकिन अगली convolutional layer original input data को नहीं देख पाएगी; वह केवल pooled output देखेगी, जो उस information के साथ पिछली layer का reduced version है।
>सामान्य क्रम में: `Conv → ReLU → Pool`, प्रत्येक 2×2 pooling window अब raw pixel intensities के बजाय feature activations (“edge present / not”) के साथ काम करती है। सबसे strong activation को बनाए रखना वास्तव में सबसे salient evidence को बनाए रखता है।

इसके बाद, आवश्यकतानुसार जितनी convolutional और pooling layers जोड़नी हों, जोड़कर हम output को flatten कर सकते हैं ताकि उसे fully connected layers में feed किया जा सके। यह batch में प्रत्येक sample के लिए tensor को 1D vector में reshape करके किया जाता है:
```python
x = x.view(-1, 64*24*24)
```
और पिछले convolutional और pooling layers द्वारा generated सभी training parameters वाले इस 1D vector के साथ, हम एक fully connected layer को इस प्रकार define कर सकते हैं:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
जो पिछली layer के flattened output को लेगी और उसे 512 hidden units में map करेगी।

ध्यान दें कि इस layer ने `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` trainable parameters जोड़े, जो convolutional layers की तुलना में एक महत्वपूर्ण वृद्धि है। ऐसा इसलिए है क्योंकि fully connected layers एक layer के प्रत्येक neuron को अगली layer के प्रत्येक neuron से connect करती हैं, जिससे parameters की संख्या बहुत अधिक हो जाती है।

अंत में, अंतिम class logits उत्पन्न करने के लिए हम एक output layer जोड़ सकते हैं:
```python
self.fc2 = nn.Linear(512, num_classes)
```
यह `(512 + 1 (bias)) * num_classes` trainable parameters जोड़ेगा, जहाँ `num_classes` classification task में classes की संख्या है (जैसे, GTSRB dataset के लिए 43)।

एक और सामान्य practice है कि overfitting को रोकने के लिए fully connected layers से पहले dropout layer जोड़ी जाए। यह इस प्रकार किया जा सकता है:
```python
self.dropout = nn.Dropout(0.5)
```
यह layer training के दौरान input units के एक अंश को random रूप से zero पर सेट करती है, जिससे specific neurons पर निर्भरता कम करके overfitting को रोकने में मदद मिलती है।

### CNN Code example
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

निम्नलिखित code कुछ training data तैयार करेगा और ऊपर परिभाषित `MY_NET` model को train करेगा। ध्यान देने योग्य कुछ interesting values:

- `EPOCHS` वह संख्या है जितनी बार training के दौरान model पूरे dataset को देखेगा। यदि EPOCH बहुत छोटा है, तो model पर्याप्त रूप से सीख नहीं पाएगा; यदि बहुत बड़ा है, तो वह overfit कर सकता है।
- `LEARNING_RATE` optimizer का step size है। छोटा learning rate धीमी convergence का कारण बन सकता है, जबकि बड़ा learning rate optimal solution से आगे निकल सकता है और convergence को रोक सकता है।
- `WEIGHT_DECAY` एक regularization term है, जो बड़े weights को penalize करके overfitting को रोकने में मदद करता है।

Training loop के संबंध में जानने योग्य कुछ interesting information:
- `criterion = nn.CrossEntropyLoss()` multi-class classification tasks के लिए उपयोग किया जाने वाला loss function है। यह softmax activation और cross-entropy loss को एक ही function में जोड़ता है, जिससे यह class logits output करने वाले models की training के लिए उपयुक्त बनता है।
- यदि model से binary classification या regression जैसे अन्य प्रकार के outputs की अपेक्षा होती, तो हम अलग loss functions का उपयोग करते, जैसे binary classification के लिए `nn.BCEWithLogitsLoss()` या regression के लिए `nn.MSELoss()`।
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` Adam optimizer को initialize करता है, जो deep learning models की training के लिए एक popular choice है। यह gradients के first और second moments के आधार पर प्रत्येक parameter के लिए learning rate को adapt करता है।
- Training task की specific requirements के आधार पर `optim.SGD` (Stochastic Gradient Descent) या `optim.RMSprop` जैसे अन्य optimizers का भी उपयोग किया जा सकता है।
- `model.train()` method model को training mode में सेट करता है, जिससे dropout और batch normalization जैसी layers evaluation की तुलना में training के दौरान अलग तरह से व्यवहार करती हैं।
- `optimizer.zero_grad()` backward pass से पहले सभी optimized tensors के gradients को clear करता है, जो आवश्यक है क्योंकि PyTorch में gradients default रूप से accumulate होते हैं। यदि उन्हें clear नहीं किया गया, तो पिछली iterations के gradients वर्तमान gradients में जुड़ जाएंगे, जिससे incorrect updates होंगे।
- `loss.backward()` model parameters के संबंध में loss के gradients compute करता है, जिनका उपयोग optimizer weights को update करने के लिए करता है।
- `optimizer.step()` computed gradients और learning rate के आधार पर model parameters को update करता है।
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

Recurrent Neural Networks (RNNs) neural networks का एक वर्ग हैं, जिन्हें time series या natural language जैसे sequential data को process करने के लिए design किया गया है। Traditional feedforward neural networks के विपरीत, RNNs में ऐसे connections होते हैं जो स्वयं पर loop back करते हैं, जिससे वे एक hidden state बनाए रख सकते हैं। यह hidden state sequence में पिछले inputs की information को capture करती है।

RNNs के मुख्य components में शामिल हैं:
- **Recurrent Layers**: ये layers input sequences को एक समय में एक time step process करती हैं और current input तथा previous hidden state के आधार पर अपनी hidden state को update करती हैं। इससे RNNs data में temporal dependencies सीख सकती हैं।
- **Hidden State**: hidden state एक vector है जो पिछले time steps की information को summarize करता है। इसे प्रत्येक time step पर update किया जाता है और current input के लिए predictions बनाने में उपयोग किया जाता है।
- **Output Layer**: output layer hidden state के आधार पर final predictions उत्पन्न करती है। कई मामलों में, RNNs का उपयोग language modeling जैसे tasks के लिए किया जाता है, जहाँ output sequence में अगले word पर probability distribution होता है।

उदाहरण के लिए, एक language model में RNN words के sequence, जैसे "The cat sat on the", को process करता है और पिछले words द्वारा दिए गए context के आधार पर अगला word predict करता है, इस मामले में "mat"।

### Long Short-Term Memory (LSTM) and Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

RNNs sequential data से जुड़े tasks, जैसे language modeling, machine translation और speech recognition, के लिए विशेष रूप से प्रभावी हैं। हालांकि, **vanishing gradients जैसी समस्याओं के कारण उन्हें long-range dependencies के साथ कठिनाई हो सकती है**।

इसे संबोधित करने के लिए Long Short-Term Memory (LSTM) और Gated Recurrent Unit (GRU) जैसी specialized architectures विकसित की गईं। ये architectures ऐसे gating mechanisms प्रस्तुत करती हैं जो information के flow को control करते हैं, जिससे वे long-range dependencies को अधिक प्रभावी ढंग से capture कर पाती हैं।

- **LSTM**: LSTM networks cell state के अंदर और बाहर information के flow को regulate करने के लिए three gates (input gate, forget gate और output gate) का उपयोग करते हैं। इससे वे लंबे sequences में information को remember या forget कर सकते हैं। input gate यह control करता है कि input और previous hidden state के आधार पर कितनी नई information जोड़ी जाए, जबकि forget gate यह control करता है कि कितनी information discard की जाए। input gate और forget gate को combine करने पर हमें new state मिलती है। अंत में, new cell state को input और previous hidden state के साथ combine करने पर हमें new hidden state भी मिलती है।
- **GRU**: GRU networks input और forget gates को एक single update gate में combine करके LSTM architecture को simplify करते हैं। इससे वे long-range dependencies को capture करते हुए computational रूप से अधिक efficient बनते हैं।

## LLMs (Large Language Models)

Large Language Models (LLMs) deep learning models का एक प्रकार हैं, जिन्हें विशेष रूप से natural language processing tasks के लिए design किया गया है। इन्हें बहुत बड़ी मात्रा में text data पर train किया जाता है और ये human-like text generate कर सकते हैं, questions का answer दे सकते हैं, languages translate कर सकते हैं और language से संबंधित कई अन्य tasks perform कर सकते हैं।
LLMs आमतौर पर transformer architectures पर आधारित होते हैं, जो sequence में words के बीच relationships को capture करने के लिए self-attention mechanisms का उपयोग करते हैं। इससे वे context को समझ सकते हैं और coherent text generate कर सकते हैं।

### Transformer Architecture <sup>[[4]](#references)</sup>
Transformer architecture कई LLMs का foundation है। इसमें encoder-decoder structure होता है, जहाँ encoder input sequence को process करता है और decoder output sequence generate करता है। Transformer architecture के मुख्य components में शामिल हैं:
- **Self-Attention Mechanism**: यह mechanism representations generate करते समय model को sequence में अलग-अलग words के महत्व को weigh करने देता है। यह words के बीच relationships के आधार पर attention scores compute करता है, जिससे model relevant context पर focus कर सकता है।
- **Multi-Head Attention**: यह component model को multiple attention heads का उपयोग करके words के बीच multiple relationships capture करने देता है। प्रत्येक head input के अलग-अलग aspects पर focus करता है।
- **Positional Encoding**: चूँकि transformers में word order की built-in notion नहीं होती, इसलिए sequence में words की position के बारे में information देने के लिए input embeddings में positional encoding जोड़ी जाती है।

## Diffusion Models <sup>[[5]](#references)</sup>
Diffusion models generative models का एक वर्ग हैं, जो diffusion process को simulate करके data generate करना सीखते हैं। ये image generation जैसे tasks के लिए विशेष रूप से प्रभावी हैं और हाल के वर्षों में लोकप्रिय हुए हैं।
Diffusion models diffusion steps की एक series के माध्यम से simple noise distribution को complex data distribution में धीरे-धीरे transform करके काम करते हैं। Diffusion models के मुख्य components में शामिल हैं:
- **Forward Diffusion Process**: यह process data में धीरे-धीरे noise जोड़ता है और उसे simple noise distribution में transform करता है। Forward diffusion process आमतौर पर noise levels की एक series द्वारा define किया जाता है, जहाँ प्रत्येक level data में जोड़ी गई noise की एक specific amount के अनुरूप होता है।
- **Reverse Diffusion Process**: यह process forward diffusion process को reverse करना सीखता है और target distribution से samples generate करने के लिए data को धीरे-धीरे denoise करता है। Reverse diffusion process को एक loss function का उपयोग करके train किया जाता है, जो model को noisy samples से original data reconstruct करने के लिए प्रोत्साहित करता है।

इसके अलावा, text prompt से image generate करने के लिए diffusion models आमतौर पर इन steps का पालन करते हैं:
1. **Text Encoding**: text prompt को text encoder (जैसे, transformer-based model) का उपयोग करके latent representation में encode किया जाता है। यह representation text के semantic meaning को capture करती है।
2. **Noise Sampling**: Gaussian distribution से एक random noise vector sample किया जाता है।
3. **Diffusion Steps**: model diffusion steps की एक series apply करता है और noise vector को धीरे-धीरे ऐसी image में transform करता है जो text prompt से correspond करती है। प्रत्येक step में image को denoise करने के लिए learned transformations apply करना शामिल होता है।

## References

- [1] [PyTorch - Neural Networks ट्यूटोरियल](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Denoising Diffusion Probabilistic Models](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
