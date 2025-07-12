# Deep Learning

{#include ../../../../../home/runner/work/HackTricks-Feed/HackTricks-Feed/src/banners/hacktricks-training.md}

## Deep Learning

Deep learning is a subset of machine learning that uses neural networks with multiple layers (deep neural networks) to model complex patterns in data. It has achieved remarkable success in various domains, including computer vision, natural language processing, and speech recognition.

### Neural Networks

Neural networks are the building blocks of deep learning. They consist of interconnected nodes (neurons) organized in layers. Each neuron receives inputs, applies a weighted sum, and passes the result through an activation function to produce an output. The layers can be categorized as follows:
- **Input Layer**: The first layer that receives the input data.
- **Hidden Layers**: Intermediate layers that perform transformations on the input data. The number of hidden layers and neurons in each layer can vary, leading to different architectures.
- **Output Layer**: The final layer that produces the output of the network, such as class probabilities in classification tasks.


### Activation Functions

When a layer of neurons processes input data, each neuron applies a weight and a bias to the input (`z = w * x + b`), where `w` is the weight, `x` is the input, and `b` is the bias. The output of the neuron is then passed through an **activation function to introduce non-linearity** into the model. This activation function basically indicates if the next neuron "should be activated and how much". This allows the network to learn complex patterns and relationships in the data, enabling it to approximate any continuous function.

Therefore, activation functions introduce non-linearity into the neural network, allowing it to learn complex relationships in the data. Common activation functions include:
- **Sigmoid**: Maps input values to a range between 0 and 1, often used in binary classification.
- **ReLU (Rectified Linear Unit)**: Outputs the input directly if it is positive; otherwise, it outputs zero. It is widely used due to its simplicity and effectiveness in training deep networks.
- **Tanh**: Maps input values to a range between -1 and 1, often used in hidden layers.
- **Softmax**: Converts raw scores into probabilities, often used in the output layer for multi-class classification.

### Backpropagation

Backpropagation is the algorithm used to train neural networks by adjusting the weights of the connections between neurons. It works by calculating the gradient of the loss function with respect to each weight and updating the weights in the opposite direction of the gradient to minimize the loss. The steps involved in backpropagation are:

1. **Forward Pass**: Compute the output of the network by passing the input through the layers and applying activation functions.
2. **Loss Calculation**: Calculate the loss (error) between the predicted output and the true target using a loss function (e.g., mean squared error for regression, cross-entropy for classification).
3. **Backward Pass**: Compute the gradients of the loss with respect to each weight using the chain rule of calculus.
4. **Weight Update**: Update the weights using an optimization algorithm (e.g., stochastic gradient descent, Adam) to minimize the loss.

## Convolutional Neural Networks (CNNs)

Convolutional Neural Networks (CNNs) are a specialized type of neural network designed for processing grid-like data, such as images. They are particularly effective in computer vision tasks due to their ability to automatically learn spatial hierarchies of features.

The main components of CNNs include:
- **Convolutional Layers**: Apply convolution operations to the input data using learnable filters (kernels) to extract local features. Each filter slides over the input and computes a dot product, producing a feature map.
- **Pooling Layers**: Downsample the feature maps to reduce their spatial dimensions while retaining important features. Common pooling operations include max pooling and average pooling.
- **Fully Connected Layers**: Connect every neuron in one layer to every neuron in the next layer, similar to traditional neural networks. These layers are typically used at the end of the network for classification tasks.

Inside a CNN **`Convolutional Layers`**, we can also distinguish between:
- **Initial Convolutional Layer**: The first convolutional layer that processes the raw input data (e.g., an image) and is useful to identify basic features like edges and textures.
- **Intermediate Convolutional Layers**: Subsequent convolutional layers that build on the features learned by the initial layer, allowing the network to learn more complex patterns and representations.
- **Final Convolutional Layer**: The last convolutional layers before the fully connected layers, which captures high-level features and prepares the data for classification.

> [!TIP]
> CNNs are particularly effective for image classification, object detection, and image segmentation tasks due to their ability to learn spatial hierarchies of features in grid-like data and reduce the number of parameters through weight sharing.
> Moreover, they work better with data supporting the feature locality principle where neighboring data (pixels) are more likely to be related than distant pixels, which might not be the case for other types of data like text.
> Furthermore, note how CNNs will be able to identify even complex features but won't be able to apply any spatial context, meaning that the same feature found in different parts of the image will be the same.

### Example defining a CNN

*Here you will find a description on how to define a Convolutional Neural Network (CNN) in PyTorch that starts with a batch of RGB images as dataset of size 48x48 and uses convolutional layers and maxpool to extract features, followed by fully connected layers for classification.*

This is how you can define 1 convolutional layer in PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Number of input channels. In case of RGB images, this is 3 (one for each color channel). If you are working with grayscale images, this would be 1.

- `out_channels`: Number of output channels (filters) that the convolutional layer will learn. This is a hyperparameter that you can adjust based on your model architecture.

- `kernel_size`: Size of the convolutional filter. A common choice is 3x3, which means the filter will cover a 3x3 area of the input image. This is like a 3×3×3 colour stamp that is used to generate the out_channels from the in_channels:
  1. Place that 3×3×3 stamp on the top-left corner of the image cube.
  2. Multiply every weight by the pixel under it, add them all, add bias → you get one number.
  3. Write that number into a blank map at position (0, 0).
  4. Slide the stamp one pixel to the right (stride = 1) and repeat until you fill a whole 48×48 grid.

- `padding`: Number of pixels added to each side of the input. Padding helps preserve the spatial dimensions of the input, allowing for more control over the output size. For example, with a 3x3 kernel an 48x48 pixel input, padding of 1 will keep the output size the same (48x48) after the convolution operation. This is because the padding adds a border of 1 pixel around the input image, allowing the kernel to slide over the edges without reducing the spatial dimensions.

Then, the number of trainable parameters in this layer is:
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 trainable parameters.

Note that a Bias (+1) is added per kernel used because the function of each convolutional layer is to learn a linear transformation of the input, which is represented by the equation:

```plaintext
Y = f(W * X + b)
```

where the `W` is the weight matrix (the learned filters, 3x3x3 = 27 params), `b` is the bias vector which is +1 for each output channel.

Note that the output of `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` will be a tensor of shape `(batch_size, 32, 48, 48)`, because 32 is the new number of generated channels of size 48x48 pixels.

Then, we could connect this convolutional layer to another convolutional layer like: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Which will add: (32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 trainable parameters and an output of shape `(batch_size, 64, 48, 48)`.

As you can see the **number of parameters grows quickly with each additional convolutional layer**, especially as the number of output channels increases.

One option to control the amount of data used is to use **max pooling** after each convolutional layer. Max pooling reduces the spatial dimensions of the feature maps, which helps to reduce the number of parameters and computational complexity while retaining important features.

It can be declared as: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. This basically indicates to use a grid of 2x2 pixels and take the maximum value from each grid to reduce the size of the feature map by half. Morever, `stride=2` means that the pooling operation will move 2 pixels at a time, in this case, preventing any overlap between the pooling regions.

With this pooling layer, the output shape after the first convolutional layer would be `(batch_size, 64, 24, 24)` after applying `self.pool1` to the output of `self.conv2`, reducing the size to 1/4th of the previous layer.

> [!TIP]
> It's important to pool after the convolutional layers to reduce the spatial dimensions of the feature maps, which helps to control the number of parameters and computational complexity while making the initial parameter learn important features.
>You can see the convolutions before a pooling layer as a way to extract features from the input data (like lines, edges), this information will still be present in the pooled output, but the next convolutional layer will not be able to see the original input data, only the pooled output, which is a reduced version of the previous layer with that information.
>In the usual order: `Conv → ReLU → Pool` each 2×2 pooling window now contends with feature activations (“edge present / not”), not raw pixel intensities. Keeping the strongest activation really does keep the most salient evidence.

Then, after adding as many convolutional and pooling layers as needed, we can flatten the output to feed it into fully connected layers. This is done by reshaping the tensor to a 1D vector for each sample in the batch:

```python
x = x.view(-1, 64*24*24)
```

And with this 1D vector with all the training parameters generated by the previous convolutional and pooling layers, we can define a fully connected layer like:

```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```

Which will take the flattened output of the previous layer and map it to 512 hidden units.

Note how this layer added `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` trainable parameters, which is a significant increase compared to the convolutional layers. This is because fully connected layers connect every neuron in one layer to every neuron in the next layer, leading to a large number of parameters.

Finally, we can add an output layer to produce the final class logits:

```python
self.fc2 = nn.Linear(512, num_classes)
```

This will add `(512 + 1 (bias)) * num_classes` trainable parameters, where `num_classes` is the number of classes in the classification task (e.g., 43 for the GTSRB dataset).

One alst common practice is to add a dropout layer before the fully connected layers to prevent overfitting. This can be done with:

```python
self.dropout = nn.Dropout(0.5)
```
This layer randomly sets a fraction of the input units to zero during training, which helps to prevent overfitting by reducing the reliance on specific neurons.

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

The following code will make up some training data and train the `MY_NET` model defined above. Some interesting values to note:

- `EPOCHS` is the number of times the model will see the entire dataset during training. If EPOCH is too small, the model may not learn enough; if too large, it may overfit.
- `LEARNING_RATE` is the step size for the optimizer. A small learning rate may lead to slow convergence, while a large one may overshoot the optimal solution and prevent convergence.
- `WEIGHT_DECAY` is a regularization term that helps prevent overfitting by penalizing large weights.

Regarding the training loop this is some interesting information to know:
- The `criterion = nn.CrossEntropyLoss()` is the loss function used for multi-class classification tasks. It combines softmax activation and cross-entropy loss in a single function, making it suitable for training models that output class logits.
    - If the model was expected to output other types of outputs, like binary classification or regression, we would use different loss functions like `nn.BCEWithLogitsLoss()` for binary classification or `nn.MSELoss()` for regression.
- The `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` initializes the Adam optimizer, which is a popular choice for training deep learning models. It adapts the learning rate for each parameter based on the first and second moments of the gradients.
    - Other optimizers like `optim.SGD` (Stochastic Gradient Descent) or `optim.RMSprop` could also be used, depending on the specific requirements of the training task.
- The `model.train()` method sets the model to training mode, enabling layers like dropout and batch normalization to behave differently during training compared to evaluation.
- `optimizer.zero_grad()` clears the gradients of all optimized tensors before the backward pass, which is necessary because gradients accumulate by default in PyTorch. If not cleared, gradients from previous iterations would be added to the current gradients, leading to incorrect updates.
- `loss.backward()` computes the gradients of the loss with respect to the model parameters, which are then used by the optimizer to update the weights.
- `optimizer.step()` updates the model parameters based on the computed gradients and the learning rate.

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



## Recurrent Neural Networks (RNNs)

Recurrent Neural Networks (RNNs) are a class of neural networks designed for processing sequential data, such as time series or natural language. Unlike traditional feedforward neural networks, RNNs have connections that loop back on themselves, allowing them to maintain a hidden state that captures information about previous inputs in the sequence.

The main components of RNNs include:
- **Recurrent Layers**: These layers process input sequences one time step at a time, updating their hidden state based on the current input and the previous hidden state. This allows RNNs to learn temporal dependencies in the data.
- **Hidden State**: The hidden state is a vector that summarizes the information from previous time steps. It is updated at each time step and is used to make predictions for the current input.
- **Output Layer**: The output layer produces the final predictions based on the hidden state. In many cases, RNNs are used for tasks like language modeling, where the output is a probability distribution over the next word in a sequence.

For example, in a language model, the RNN processes a sequence of words, for example, "The cat sat on the" and predicts the next word based on the context provided by the previous words, in this case, "mat".

### Long Short-Term Memory (LSTM) and Gated Recurrent Unit (GRU)

RNNs are particularly effective for tasks involving sequential data, such as language modeling, machine translation, and speech recognition. However, they can struggle with **long-range dependencies due to issues like vanishing gradients**.

To address this, specialized architectures like Long Short-Term Memory (LSTM) and Gated Recurrent Unit (GRU) were developed. These architectures introduce gating mechanisms that control the flow of information, allowing them to capture long-range dependencies more effectively.

- **LSTM**: LSTM networks use three gates (input gate, forget gate, and output gate) to regulate the flow of information in and out of the cell state, enabling them to remember or forget information over long sequences. The input gate controls how much new information to add based on the input and the previous hidden state, the forget gate controls how much information to discard. Combining the input gate and the forget gate we get the new state. Finally, combining the new cell state, with the input and the previous hidden state we also get the new hidden state.
- **GRU**: GRU networks simplify the LSTM architecture by combining the input and forget gates into a single update gate, making them computationally more efficient while still capturing long-range dependencies.

## LLMs (Large Language Models)

Large Language Models (LLMs) are a type of deep learning model specifically designed for natural language processing tasks. They are trained on vast amounts of text data and can generate human-like text, answer questions, translate languages, and perform various other language-related tasks.
LLMs are typically based on transformer architectures, which use self-attention mechanisms to capture relationships between words in a sequence, allowing them to understand context and generate coherent text.

### Transformer Architecture
The transformer architecture is the foundation of many LLMs. It consists of an encoder-decoder structure, where the encoder processes the input sequence and the decoder generates the output sequence. The key components of the transformer architecture include:
- **Self-Attention Mechanism**: This mechanism allows the model to weigh the importance of different words in a sequence when generating representations. It computes attention scores based on the relationships between words, enabling the model to focus on relevant context.
- **Multi-Head Attention**: This component allows the model to capture multiple relationships between words by using multiple attention heads, each focusing on different aspects of the input.
- **Positional Encoding**: Since transformers do not have a built-in notion of word order, positional encoding is added to the input embeddings to provide information about the position of words in the sequence.

## Diffusion Models
Diffusion models are a class of generative models that learn to generate data by simulating a diffusion process. They are particularly effective for tasks like image generation and have gained popularity in recent years.
Diffusion models work by gradually transforming a simple noise distribution into a complex data distribution through a series of diffusion steps. The key components of diffusion models include:
- **Forward Diffusion Process**: This process gradually adds noise to the data, transforming it into a simple noise distribution. The forward diffusion process is typically defined by a series of noise levels, where each level corresponds to a specific amount of noise added to the data.
- **Reverse Diffusion Process**: This process learns to reverse the forward diffusion process, gradually denoising the data to generate samples from the target distribution. The reverse diffusion process is trained using a loss function that encourages the model to reconstruct the original data from noisy samples.

Moreover, to generate an image from a text prompt, diffusion models typically follow these steps:
1. **Text Encoding**: The text prompt is encoded into a latent representation using a text encoder (e.g., a transformer-based model). This representation captures the semantic meaning of the text.
2. **Noise Sampling**: A random noise vector is sampled from a Gaussian distribution.
3. **Diffusion Steps**: The model applies a series of diffusion steps, gradually transforming the noise vector into an image that corresponds to the text prompt. Each step involves applying learned transformations to denoise the image.


{#include ../../../../../home/runner/work/HackTricks-Feed/HackTricks-Feed/src/banners/hacktricks-training.md}
