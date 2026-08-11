# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning <sup>[[1]](#references)</sup>

Le deep learning est un sous-ensemble du machine learning qui utilise des réseaux neuronaux comportant plusieurs couches (réseaux neuronaux profonds) pour modéliser des motifs complexes dans les données. Il a connu un succès remarquable dans divers domaines, notamment la vision par ordinateur, le traitement automatique du langage naturel et la reconnaissance vocale.

### Réseaux neuronaux

Les réseaux neuronaux sont les éléments constitutifs du deep learning. Ils se composent de nœuds interconnectés (neurones) organisés en couches. Chaque neurone reçoit des entrées, applique une somme pondérée, puis fait passer le résultat dans une fonction d’activation afin de produire une sortie. Les couches peuvent être classées comme suit :
- **Couche d’entrée** : première couche qui reçoit les données d’entrée.
- **Couches cachées** : couches intermédiaires qui effectuent des transformations sur les données d’entrée. Le nombre de couches cachées et de neurones dans chaque couche peut varier, ce qui conduit à différentes architectures.
- **Couche de sortie** : dernière couche qui produit la sortie du réseau, comme les probabilités des classes dans les tâches de classification.


### Fonctions d’activation

Lorsqu’une couche de neurones traite des données d’entrée, chaque neurone applique un poids et un biais à l’entrée (`z = w * x + b`), où `w` est le poids, `x` est l’entrée et `b` est le biais. La sortie du neurone passe ensuite par une **fonction d’activation afin d’introduire de la non-linéarité** dans le modèle. Cette fonction d’activation indique essentiellement si le neurone suivant « doit être activé et dans quelle mesure ». Cela permet au réseau d’apprendre des motifs et des relations complexes dans les données, et donc d’approximer toute fonction continue.

Ainsi, les fonctions d’activation introduisent de la non-linéarité dans le réseau neuronal, ce qui lui permet d’apprendre des relations complexes dans les données. Les fonctions d’activation courantes comprennent :
- **Sigmoid** : associe les valeurs d’entrée à une plage comprise entre 0 et 1, et est souvent utilisée pour la classification binaire.
- **ReLU (Rectified Linear Unit)** : renvoie directement l’entrée si celle-ci est positive ; sinon, elle renvoie zéro. Elle est largement utilisée en raison de sa simplicité et de son efficacité lors de l’entraînement de réseaux profonds.
- **Tanh** : associe les valeurs d’entrée à une plage comprise entre -1 et 1, et est souvent utilisée dans les couches cachées.
- **Softmax** : convertit les scores bruts en probabilités, et est souvent utilisée dans la couche de sortie pour la classification multi-classes.

### Rétropropagation

La rétropropagation est l’algorithme utilisé pour entraîner les réseaux neuronaux en ajustant les poids des connexions entre les neurones. Il fonctionne en calculant le gradient de la fonction de perte par rapport à chaque poids, puis en mettant à jour les poids dans la direction opposée au gradient afin de minimiser la perte. Les étapes de la rétropropagation sont les suivantes :

1. **Passage avant** : calculer la sortie du réseau en faisant passer l’entrée à travers les couches et en appliquant les fonctions d’activation.
2. **Calcul de la perte** : calculer la perte (erreur) entre la sortie prédite et la vraie cible à l’aide d’une fonction de perte (par exemple, l’erreur quadratique moyenne pour la régression et l’entropie croisée pour la classification).
3. **Passage arrière** : calculer les gradients de la perte par rapport à chaque poids à l’aide de la règle de dérivation en chaîne.
4. **Mise à jour des poids** : mettre à jour les poids à l’aide d’un algorithme d’optimisation (par exemple, la descente de gradient stochastique ou Adam) afin de minimiser la perte.

## Réseaux neuronaux convolutifs (CNN) <sup>[[2]](#references)</sup>

Les réseaux neuronaux convolutifs (CNN) sont un type spécialisé de réseau neuronal conçu pour traiter des données organisées en grille, comme les images. Ils sont particulièrement efficaces pour les tâches de vision par ordinateur grâce à leur capacité à apprendre automatiquement des hiérarchies spatiales de caractéristiques.

Les principaux composants des CNN comprennent :
- **Couches convolutives** : appliquent des opérations de convolution aux données d’entrée à l’aide de filtres apprenables (kernels) afin d’extraire des caractéristiques locales. Chaque filtre se déplace sur l’entrée et calcule un produit scalaire, produisant ainsi une feature map.
- **Couches de pooling** : réduisent la résolution des feature maps afin de diminuer leurs dimensions spatiales tout en conservant les caractéristiques importantes. Les opérations de pooling courantes comprennent le max pooling et l’average pooling.
- **Couches entièrement connectées** : connectent chaque neurone d’une couche à chaque neurone de la couche suivante, comme dans les réseaux neuronaux traditionnels. Ces couches sont généralement utilisées à la fin du réseau pour les tâches de classification.

Dans les **`Convolutional Layers`** d’un CNN, on peut également distinguer :
- **Couche convolutive initiale** : première couche convolutive qui traite les données d’entrée brutes (par exemple, une image) et qui est utile pour identifier des caractéristiques de base comme les contours et les textures.
- **Couches convolutives intermédiaires** : couches convolutives suivantes qui s’appuient sur les caractéristiques apprises par la couche initiale, permettant au réseau d’apprendre des motifs et des représentations plus complexes.
- **Couche convolutive finale** : dernières couches convolutives avant les couches entièrement connectées, qui capturent les caractéristiques de haut niveau et préparent les données pour la classification.

> [!TIP]
> Les CNN sont particulièrement efficaces pour les tâches de classification d’images, de détection d’objets et de segmentation d’images grâce à leur capacité à apprendre des hiérarchies spatiales de caractéristiques dans des données organisées en grille et à réduire le nombre de paramètres grâce au partage des poids.
> De plus, ils fonctionnent mieux avec les données respectant le principe de localité des caractéristiques, selon lequel les données voisines (les pixels) sont plus susceptibles d’être liées que les pixels éloignés, ce qui peut ne pas être le cas pour d’autres types de données comme le texte.
> En outre, notez que les CNN sont capables d’identifier même des caractéristiques complexes, mais qu’ils ne peuvent pas appliquer de contexte spatial. Cela signifie qu’une même caractéristique trouvée dans différentes parties de l’image sera considérée comme identique.

### Exemple de définition d’un CNN

*Vous trouverez ici une description de la manière de définir un réseau neuronal convolutif (CNN) dans PyTorch, qui commence avec un batch d’images RGB de taille 48x48 comme dataset et utilise des couches convolutives ainsi que le maxpool pour extraire des caractéristiques, suivis de couches entièrement connectées pour la classification.*

Voici comment définir 1 couche convolutive dans PyTorch : `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels` : nombre de canaux d’entrée. Dans le cas d’images RGB, ce nombre est de 3 (un pour chaque canal de couleur). Pour des images en niveaux de gris, ce nombre serait de 1.

- `out_channels` : nombre de canaux de sortie (filtres) que la couche convolutive apprendra. Il s’agit d’un hyperparamètre que vous pouvez ajuster en fonction de l’architecture de votre modèle.

- `kernel_size` : taille du filtre convolutif. Un choix courant est 3x3, ce qui signifie que le filtre couvrira une zone de 3x3 de l’image d’entrée. Il s’agit d’une sorte de tampon de couleur 3×3×3 utilisé pour générer les `out_channels` à partir des `in_channels` :
1. Placez ce tampon 3×3×3 dans le coin supérieur gauche du cube d’image.
2. Multipliez chaque poids par le pixel situé en dessous, additionnez-les tous, puis ajoutez le biais → vous obtenez un nombre.
3. Écrivez ce nombre dans une carte vide à la position (0, 0).
4. Faites glisser le tampon d’un pixel vers la droite (stride = 1) et répétez l’opération jusqu’à remplir toute une grille de 48×48.

- `padding` : nombre de pixels ajoutés de chaque côté de l’entrée. Le padding aide à préserver les dimensions spatiales de l’entrée, ce qui permet de mieux contrôler la taille de sortie. Par exemple, avec un kernel 3x3 et une entrée de 48x48 pixels, un padding de 1 conservera la même taille de sortie (48x48) après l’opération de convolution. Cela s’explique par le fait que le padding ajoute une bordure d’un pixel autour de l’image d’entrée, permettant au kernel de se déplacer sur les bords sans réduire les dimensions spatiales.

Le nombre de paramètres entraînables de cette couche est donc :
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 paramètres entraînables.

Notez qu’un Bias (+1) est ajouté pour chaque kernel utilisé, car la fonction de chaque couche convolutive est d’apprendre une transformation linéaire de l’entrée, représentée par l’équation :
```plaintext
Y = f(W * X + b)
```
où `W` est la matrice des poids (les filtres appris, 3x3x3 = 27 paramètres), `b` est le vecteur de biais qui vaut +1 pour chaque canal de sortie.

Notez que la sortie de `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` sera un tenseur de forme `(batch_size, 32, 48, 48)`, car 32 est le nouveau nombre de canaux générés de taille 48x48 pixels.

Ensuite, nous pouvons connecter cette couche convolutionnelle à une autre couche convolutionnelle comme ceci : `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Ce qui ajoutera : (32x3x3 (taille du kernel) + 1 (biais)) x 64 (out_channels) = 18,496 paramètres entraînables et une sortie de forme `(batch_size, 64, 48, 48)`.

Comme vous pouvez le constater, le **nombre de paramètres augmente rapidement avec chaque couche convolutionnelle supplémentaire**, en particulier lorsque le nombre de canaux de sortie augmente.

Une option pour contrôler la quantité de données utilisée consiste à utiliser le **max pooling** après chaque couche convolutionnelle. Le max pooling réduit les dimensions spatiales des feature maps, ce qui contribue à réduire le nombre de paramètres et la complexité computationnelle tout en conservant les caractéristiques importantes.

Il peut être déclaré ainsi : `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Cela indique essentiellement d'utiliser une grille de 2x2 pixels et de prendre la valeur maximale de chaque grille afin de réduire de moitié la taille de la feature map. De plus, `stride=2` signifie que l'opération de pooling se déplace de 2 pixels à la fois, ce qui empêche ici tout chevauchement entre les régions de pooling.

Avec cette couche de pooling, la forme de sortie après la première couche convolutionnelle serait `(batch_size, 64, 24, 24)` après l'application de `self.pool1` à la sortie de `self.conv2`, réduisant la taille au quart de celle de la couche précédente.

> [!TIP]
> Il est important d'appliquer le pooling après les couches convolutionnelles afin de réduire les dimensions spatiales des feature maps, ce qui aide à contrôler le nombre de paramètres et la complexité computationnelle, tout en permettant aux paramètres initiaux d'apprendre des caractéristiques importantes.
>Vous pouvez considérer les convolutions précédant une couche de pooling comme un moyen d'extraire des caractéristiques des données d'entrée (comme des lignes ou des contours). Ces informations seront toujours présentes dans la sortie après le pooling, mais la couche convolutionnelle suivante ne pourra pas voir les données d'entrée originales, uniquement la sortie après le pooling, qui est une version réduite de la couche précédente contenant ces informations.
>Dans l'ordre habituel : `Conv → ReLU → Pool`, chaque fenêtre de pooling 2×2 traite désormais des activations de caractéristiques (« contour présent / absent »), et non des intensités brutes des pixels. Conserver l'activation la plus forte permet réellement de conserver l'indice le plus saillant.

Ensuite, après avoir ajouté autant de couches convolutionnelles et de pooling que nécessaire, nous pouvons aplatir la sortie pour l'envoyer dans des couches entièrement connectées. Cela se fait en remodelant le tenseur en un vecteur 1D pour chaque échantillon du batch :
```python
x = x.view(-1, 64*24*24)
```
Et avec ce vecteur 1D contenant tous les paramètres d'entraînement générés par les précédentes couches de convolution et de pooling, nous pouvons définir une couche entièrement connectée comme suit :
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Qui prendra la sortie aplatie de la couche précédente et la projettera sur 512 unités cachées.

Notez que cette couche ajoute `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` paramètres entraînables, ce qui représente une augmentation significative par rapport aux couches convolutionnelles. Cela s’explique par le fait que les couches entièrement connectées relient chaque neurone d’une couche à chaque neurone de la couche suivante, ce qui entraîne un grand nombre de paramètres.

Enfin, nous pouvons ajouter une couche de sortie afin de produire les logits finaux des classes :
```python
self.fc2 = nn.Linear(512, num_classes)
```
Cela ajoutera `(512 + 1 (bias)) * num_classes` paramètres entraînables, où `num_classes` correspond au nombre de classes dans la tâche de classification (par exemple, 43 pour le dataset GTSRB).

Une autre pratique courante consiste à ajouter une couche de dropout avant les couches fully connected afin d'éviter le surapprentissage. Cela peut être fait avec :
```python
self.dropout = nn.Dropout(0.5)
```
Cette couche met aléatoirement une fraction des unités d’entrée à zéro pendant l’entraînement, ce qui aide à prévenir le surapprentissage en réduisant la dépendance à certains neurones.

### Exemple de code CNN
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
### Exemple d'entraînement de code CNN

Le code suivant va générer des données d'entraînement et entraîner le modèle `MY_NET` défini ci-dessus. Voici quelques valeurs intéressantes à noter :

- `EPOCHS` correspond au nombre de fois où le modèle verra l'ensemble du dataset pendant l'entraînement. Si EPOCH est trop petit, le modèle risque de ne pas apprendre suffisamment ; s'il est trop grand, il risque de surapprendre.
- `LEARNING_RATE` correspond à la taille du pas de l'optimizer. Un learning rate faible peut entraîner une convergence lente, tandis qu'un learning rate élevé peut dépasser la solution optimale et empêcher la convergence.
- `WEIGHT_DECAY` est un terme de régularisation qui aide à prévenir le surapprentissage en pénalisant les poids élevés.

Concernant la boucle d'entraînement, voici quelques informations intéressantes à connaître :
- `criterion = nn.CrossEntropyLoss()` est la fonction de perte utilisée pour les tâches de classification multi-classes. Elle combine l'activation softmax et la cross-entropy loss en une seule fonction, ce qui la rend adaptée à l'entraînement de modèles qui produisent des logits de classes.
- Si le modèle devait produire d'autres types de sorties, comme une classification binaire ou une régression, nous utiliserions différentes fonctions de perte, telles que `nn.BCEWithLogitsLoss()` pour la classification binaire ou `nn.MSELoss()` pour la régression.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` initialise l'optimizer Adam, un choix courant pour l'entraînement des modèles de deep learning. Il adapte le learning rate de chaque paramètre en fonction des premier et deuxième moments des gradients.
- D'autres optimizers, comme `optim.SGD` (Stochastic Gradient Descent) ou `optim.RMSprop`, peuvent également être utilisés selon les exigences spécifiques de la tâche d'entraînement.
- La méthode `model.train()` place le modèle en mode entraînement, ce qui permet aux layers comme dropout et batch normalization de se comporter différemment pendant l'entraînement et l'évaluation.
- `optimizer.zero_grad()` efface les gradients de tous les tensors optimisés avant le backward pass, ce qui est nécessaire car les gradients s'accumulent par défaut dans PyTorch. S'ils ne sont pas effacés, les gradients des itérations précédentes seraient ajoutés aux gradients actuels, ce qui entraînerait des mises à jour incorrectes.
- `loss.backward()` calcule les gradients de la loss par rapport aux paramètres du modèle, qui sont ensuite utilisés par l'optimizer pour mettre à jour les poids.
- `optimizer.step()` met à jour les paramètres du modèle en fonction des gradients calculés et du learning rate.
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
## Réseaux neuronaux récurrents (RNNs) <sup>[[3]](#references)</sup>

Les réseaux neuronaux récurrents (RNNs) sont une classe de réseaux neuronaux conçus pour traiter des données séquentielles, telles que des séries temporelles ou du langage naturel. Contrairement aux réseaux neuronaux feedforward traditionnels, les RNNs possèdent des connexions qui bouclent sur elles-mêmes, ce qui leur permet de maintenir un état caché capturant les informations des entrées précédentes de la séquence.

Les principaux composants des RNNs incluent :
- **Couches récurrentes** : Ces couches traitent les séquences d'entrée une étape temporelle à la fois, en mettant à jour leur état caché en fonction de l'entrée actuelle et de l'état caché précédent. Cela permet aux RNNs d'apprendre les dépendances temporelles présentes dans les données.
- **État caché** : L'état caché est un vecteur qui résume les informations des étapes temporelles précédentes. Il est mis à jour à chaque étape temporelle et est utilisé pour effectuer des prédictions pour l'entrée actuelle.
- **Couche de sortie** : La couche de sortie produit les prédictions finales en fonction de l'état caché. Dans de nombreux cas, les RNNs sont utilisés pour des tâches comme la modélisation du langage, où la sortie est une distribution de probabilités sur le mot suivant d'une séquence.

Par exemple, dans un modèle de langage, le RNN traite une séquence de mots, par exemple, « The cat sat on the », et prédit le mot suivant en fonction du contexte fourni par les mots précédents, dans ce cas, « mat ».

### Long Short-Term Memory (LSTM) et Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

Les RNNs sont particulièrement efficaces pour les tâches impliquant des données séquentielles, telles que la modélisation du langage, la traduction automatique et la reconnaissance vocale. Cependant, ils peuvent rencontrer des difficultés avec les **dépendances à longue portée en raison de problèmes tels que la disparition des gradients**.

Pour résoudre ce problème, des architectures spécialisées comme Long Short-Term Memory (LSTM) et Gated Recurrent Unit (GRU) ont été développées. Ces architectures introduisent des mécanismes de contrôle qui régulent le flux d'informations, leur permettant de capturer plus efficacement les dépendances à longue portée.

- **LSTM** : Les réseaux LSTM utilisent trois portes (porte d'entrée, porte d'oubli et porte de sortie) pour réguler le flux d'informations entrant et sortant de l'état de la cellule, ce qui leur permet de mémoriser ou d'oublier des informations sur de longues séquences. La porte d'entrée contrôle la quantité de nouvelles informations à ajouter en fonction de l'entrée et de l'état caché précédent, tandis que la porte d'oubli contrôle la quantité d'informations à supprimer. En combinant la porte d'entrée et la porte d'oubli, on obtient le nouvel état. Enfin, en combinant le nouvel état de la cellule avec l'entrée et l'état caché précédent, on obtient également le nouvel état caché.
- **GRU** : Les réseaux GRU simplifient l'architecture LSTM en combinant les portes d'entrée et d'oubli en une seule porte de mise à jour, ce qui les rend plus efficaces sur le plan computationnel tout en capturant les dépendances à longue portée.

## LLMs (Large Language Models)

Les Large Language Models (LLMs) sont un type de modèle de deep learning spécifiquement conçu pour les tâches de traitement du langage naturel. Ils sont entraînés sur de vastes quantités de données textuelles et peuvent générer du texte ressemblant à celui produit par un humain, répondre à des questions, traduire des langues et effectuer diverses autres tâches liées au langage.
Les LLMs sont généralement basés sur des architectures transformer, qui utilisent des mécanismes de self-attention pour capturer les relations entre les mots d'une séquence, ce qui leur permet de comprendre le contexte et de générer un texte cohérent.

### Architecture Transformer <sup>[[4]](#references)</sup>
L'architecture transformer constitue la base de nombreux LLMs. Elle se compose d'une structure encodeur-décodeur, dans laquelle l'encodeur traite la séquence d'entrée et le décodeur génère la séquence de sortie. Les principaux composants de l'architecture transformer incluent :
- **Mécanisme de self-attention** : Ce mécanisme permet au modèle de pondérer l'importance de différents mots d'une séquence lors de la génération des représentations. Il calcule des scores d'attention en fonction des relations entre les mots, permettant au modèle de se concentrer sur le contexte pertinent.
- **Attention multi-têtes** : Ce composant permet au modèle de capturer plusieurs relations entre les mots en utilisant plusieurs têtes d'attention, chacune se concentrant sur différents aspects de l'entrée.
- **Encodage positionnel** : Comme les transformers ne disposent pas d'une notion intégrée de l'ordre des mots, un encodage positionnel est ajouté aux embeddings d'entrée afin de fournir des informations sur la position des mots dans la séquence.

## Modèles de diffusion <sup>[[5]](#references)</sup>
Les modèles de diffusion sont une classe de modèles génératifs qui apprennent à générer des données en simulant un processus de diffusion. Ils sont particulièrement efficaces pour des tâches comme la génération d'images et ont gagné en popularité ces dernières années.
Les modèles de diffusion fonctionnent en transformant progressivement une distribution simple de bruit en une distribution complexe de données au moyen d'une série d'étapes de diffusion. Les principaux composants des modèles de diffusion incluent :
- **Processus de diffusion directe** : Ce processus ajoute progressivement du bruit aux données, les transformant en une distribution simple de bruit. Le processus de diffusion directe est généralement défini par une série de niveaux de bruit, chaque niveau correspondant à une quantité spécifique de bruit ajoutée aux données.
- **Processus de diffusion inverse** : Ce processus apprend à inverser le processus de diffusion directe, en débruitant progressivement les données afin de générer des échantillons de la distribution cible. Le processus de diffusion inverse est entraîné à l'aide d'une fonction de perte qui encourage le modèle à reconstruire les données originales à partir d'échantillons bruités.

De plus, pour générer une image à partir d'un prompt textuel, les modèles de diffusion suivent généralement les étapes suivantes :
1. **Encodage du texte** : Le prompt textuel est encodé en une représentation latente à l'aide d'un encodeur de texte (par exemple, un modèle basé sur un transformer). Cette représentation capture la signification sémantique du texte.
2. **Échantillonnage du bruit** : Un vecteur de bruit aléatoire est échantillonné à partir d'une distribution gaussienne.
3. **Étapes de diffusion** : Le modèle applique une série d'étapes de diffusion, transformant progressivement le vecteur de bruit en une image correspondant au prompt textuel. Chaque étape implique l'application de transformations apprises afin de débruiter l'image.

## References

- [1] [PyTorch - Tutoriel sur les réseaux neuronaux](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Modèles probabilistes de diffusion pour le débruitage](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
