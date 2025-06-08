# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning

L'apprentissage profond est un sous-ensemble de l'apprentissage automatique qui utilise des réseaux de neurones avec plusieurs couches (réseaux de neurones profonds) pour modéliser des motifs complexes dans les données. Il a connu un succès remarquable dans divers domaines, y compris la vision par ordinateur, le traitement du langage naturel et la reconnaissance vocale.

### Neural Networks

Les réseaux de neurones sont les éléments de base de l'apprentissage profond. Ils se composent de nœuds interconnectés (neurones) organisés en couches. Chaque neurone reçoit des entrées, applique une somme pondérée et passe le résultat à travers une fonction d'activation pour produire une sortie. Les couches peuvent être catégorisées comme suit :
- **Input Layer** : La première couche qui reçoit les données d'entrée.
- **Hidden Layers** : Couches intermédiaires qui effectuent des transformations sur les données d'entrée. Le nombre de couches cachées et de neurones dans chaque couche peut varier, conduisant à différentes architectures.
- **Output Layer** : La dernière couche qui produit la sortie du réseau, comme les probabilités de classe dans les tâches de classification.

### Activation Functions

Lorsqu'une couche de neurones traite des données d'entrée, chaque neurone applique un poids et un biais à l'entrée (`z = w * x + b`), où `w` est le poids, `x` est l'entrée, et `b` est le biais. La sortie du neurone est ensuite passée à travers une **fonction d'activation pour introduire de la non-linéarité** dans le modèle. Cette fonction d'activation indique essentiellement si le neurone suivant "doit être activé et dans quelle mesure". Cela permet au réseau d'apprendre des motifs et des relations complexes dans les données, lui permettant d'approximer n'importe quelle fonction continue.

Par conséquent, les fonctions d'activation introduisent de la non-linéarité dans le réseau de neurones, lui permettant d'apprendre des relations complexes dans les données. Les fonctions d'activation courantes incluent :
- **Sigmoid** : Mappe les valeurs d'entrée à une plage entre 0 et 1, souvent utilisé dans la classification binaire.
- **ReLU (Rectified Linear Unit)** : Sort l'entrée directement si elle est positive ; sinon, elle sort zéro. Elle est largement utilisée en raison de sa simplicité et de son efficacité dans l'entraînement de réseaux profonds.
- **Tanh** : Mappe les valeurs d'entrée à une plage entre -1 et 1, souvent utilisé dans les couches cachées.
- **Softmax** : Convertit les scores bruts en probabilités, souvent utilisé dans la couche de sortie pour la classification multi-classe.

### Backpropagation

La rétropropagation est l'algorithme utilisé pour entraîner les réseaux de neurones en ajustant les poids des connexions entre les neurones. Il fonctionne en calculant le gradient de la fonction de perte par rapport à chaque poids et en mettant à jour les poids dans la direction opposée du gradient pour minimiser la perte. Les étapes impliquées dans la rétropropagation sont :

1. **Forward Pass** : Calculer la sortie du réseau en passant l'entrée à travers les couches et en appliquant des fonctions d'activation.
2. **Loss Calculation** : Calculer la perte (erreur) entre la sortie prédite et la véritable cible en utilisant une fonction de perte (par exemple, l'erreur quadratique moyenne pour la régression, l'entropie croisée pour la classification).
3. **Backward Pass** : Calculer les gradients de la perte par rapport à chaque poids en utilisant la règle de chaîne du calcul.
4. **Weight Update** : Mettre à jour les poids en utilisant un algorithme d'optimisation (par exemple, la descente de gradient stochastique, Adam) pour minimiser la perte.

## Convolutional Neural Networks (CNNs)

Les réseaux de neurones convolutionnels (CNNs) sont un type spécialisé de réseau de neurones conçu pour traiter des données en grille, telles que des images. Ils sont particulièrement efficaces dans les tâches de vision par ordinateur en raison de leur capacité à apprendre automatiquement des hiérarchies spatiales de caractéristiques.

Les principaux composants des CNNs incluent :
- **Convolutional Layers** : Appliquent des opérations de convolution aux données d'entrée en utilisant des filtres (kernels) apprenables pour extraire des caractéristiques locales. Chaque filtre glisse sur l'entrée et calcule un produit scalaire, produisant une carte de caractéristiques.
- **Pooling Layers** : Réduisent les cartes de caractéristiques pour diminuer leurs dimensions spatiales tout en conservant des caractéristiques importantes. Les opérations de pooling courantes incluent le max pooling et l'average pooling.
- **Fully Connected Layers** : Connectent chaque neurone d'une couche à chaque neurone de la couche suivante, similaire aux réseaux de neurones traditionnels. Ces couches sont généralement utilisées à la fin du réseau pour des tâches de classification.

À l'intérieur d'un CNN **`Convolutional Layers`**, nous pouvons également distinguer entre :
- **Initial Convolutional Layer** : La première couche convolutionnelle qui traite les données d'entrée brutes (par exemple, une image) et est utile pour identifier des caractéristiques de base comme les bords et les textures.
- **Intermediate Convolutional Layers** : Couches convolutionnelles suivantes qui s'appuient sur les caractéristiques apprises par la couche initiale, permettant au réseau d'apprendre des motifs et des représentations plus complexes.
- **Final Convolutional Layer** : Les dernières couches convolutionnelles avant les couches entièrement connectées, qui capturent des caractéristiques de haut niveau et préparent les données pour la classification.

> [!TIP]
> Les CNNs sont particulièrement efficaces pour la classification d'images, la détection d'objets et les tâches de segmentation d'images en raison de leur capacité à apprendre des hiérarchies spatiales de caractéristiques dans des données en grille et à réduire le nombre de paramètres grâce au partage de poids.
> De plus, ils fonctionnent mieux avec des données soutenant le principe de localité des caractéristiques où les données voisines (pixels) sont plus susceptibles d'être liées que des pixels éloignés, ce qui pourrait ne pas être le cas pour d'autres types de données comme le texte.
> En outre, notez comment les CNNs seront capables d'identifier même des caractéristiques complexes mais ne pourront pas appliquer de contexte spatial, ce qui signifie que la même caractéristique trouvée dans différentes parties de l'image sera la même.

### Example defining a CNN

*Ici, vous trouverez une description sur la façon de définir un réseau de neurones convolutionnel (CNN) dans PyTorch qui commence avec un lot d'images RGB comme ensemble de données de taille 48x48 et utilise des couches convolutionnelles et maxpool pour extraire des caractéristiques, suivies de couches entièrement connectées pour la classification.*

C'est ainsi que vous pouvez définir 1 couche convolutionnelle dans PyTorch : `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels` : Nombre de canaux d'entrée. Dans le cas des images RGB, c'est 3 (un pour chaque canal de couleur). Si vous travaillez avec des images en niveaux de gris, ce serait 1.

- `out_channels` : Nombre de canaux de sortie (filtres) que la couche convolutionnelle apprendra. C'est un hyperparamètre que vous pouvez ajuster en fonction de l'architecture de votre modèle.

- `kernel_size` : Taille du filtre convolutionnel. Un choix courant est 3x3, ce qui signifie que le filtre couvrira une zone de 3x3 de l'image d'entrée. C'est comme un tampon de couleur 3×3×3 qui est utilisé pour générer les out_channels à partir des in_channels :
1. Placez ce tampon 3×3×3 dans le coin supérieur gauche du cube d'image.
2. Multipliez chaque poids par le pixel en dessous, additionnez-les tous, ajoutez le biais → vous obtenez un nombre.
3. Écrivez ce nombre dans une carte vide à la position (0, 0).
4. Faites glisser le tampon d'un pixel vers la droite (stride = 1) et répétez jusqu'à remplir une grille entière de 48×48.

- `padding` : Nombre de pixels ajoutés à chaque côté de l'entrée. Le padding aide à préserver les dimensions spatiales de l'entrée, permettant un meilleur contrôle sur la taille de sortie. Par exemple, avec un noyau de 3x3 et une entrée de 48x48 pixels, un padding de 1 maintiendra la taille de sortie identique (48x48) après l'opération de convolution. Cela est dû au fait que le padding ajoute une bordure de 1 pixel autour de l'image d'entrée, permettant au noyau de glisser sur les bords sans réduire les dimensions spatiales.

Ensuite, le nombre de paramètres entraînables dans cette couche est :
- (3x3x3 (taille du noyau) + 1 (biais)) x 32 (out_channels) = 896 paramètres entraînables.

Notez qu'un biais (+1) est ajouté par noyau utilisé car la fonction de chaque couche convolutionnelle est d'apprendre une transformation linéaire de l'entrée, qui est représentée par l'équation :
```plaintext
Y = f(W * X + b)
```
où le `W` est la matrice de poids (les filtres appris, 3x3x3 = 27 params), `b` est le vecteur de biais qui est +1 pour chaque canal de sortie.

Notez que la sortie de `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` sera un tenseur de forme `(batch_size, 32, 48, 48)`, car 32 est le nouveau nombre de canaux générés de taille 48x48 pixels.

Ensuite, nous pourrions connecter cette couche convolutionnelle à une autre couche convolutionnelle comme : `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Ce qui ajoutera : (32x3x3 (taille du noyau) + 1 (biais)) x 64 (out_channels) = 18,496 paramètres entraînables et une sortie de forme `(batch_size, 64, 48, 48)`.

Comme vous pouvez le voir, le **nombre de paramètres augmente rapidement avec chaque couche convolutionnelle supplémentaire**, surtout à mesure que le nombre de canaux de sortie augmente.

Une option pour contrôler la quantité de données utilisées est d'utiliser **max pooling** après chaque couche convolutionnelle. Le max pooling réduit les dimensions spatiales des cartes de caractéristiques, ce qui aide à réduire le nombre de paramètres et la complexité computationnelle tout en conservant des caractéristiques importantes.

Il peut être déclaré comme : `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Cela indique essentiellement d'utiliser une grille de 2x2 pixels et de prendre la valeur maximale de chaque grille pour réduire la taille de la carte de caractéristiques de moitié. De plus, `stride=2` signifie que l'opération de pooling se déplacera de 2 pixels à la fois, dans ce cas, empêchant tout chevauchement entre les régions de pooling.

Avec cette couche de pooling, la forme de sortie après la première couche convolutionnelle serait `(batch_size, 64, 24, 24)` après avoir appliqué `self.pool1` à la sortie de `self.conv2`, réduisant la taille à 1/4 de celle de la couche précédente.

> [!TIP]
> Il est important de faire du pooling après les couches convolutionnelles pour réduire les dimensions spatiales des cartes de caractéristiques, ce qui aide à contrôler le nombre de paramètres et la complexité computationnelle tout en permettant aux paramètres initiaux d'apprendre des caractéristiques importantes.
> Vous pouvez voir les convolutions avant une couche de pooling comme un moyen d'extraire des caractéristiques des données d'entrée (comme des lignes, des bords), cette information sera toujours présente dans la sortie poolée, mais la prochaine couche convolutionnelle ne pourra pas voir les données d'entrée originales, seulement la sortie poolée, qui est une version réduite de la couche précédente avec cette information.
> Dans l'ordre habituel : `Conv → ReLU → Pool` chaque fenêtre de pooling 2×2 se confronte maintenant aux activations des caractéristiques (“bord présent / non”), pas aux intensités de pixels brutes. Garder la plus forte activation permet vraiment de conserver les preuves les plus saillantes.

Ensuite, après avoir ajouté autant de couches convolutionnelles et de pooling que nécessaire, nous pouvons aplatir la sortie pour l'alimenter dans des couches entièrement connectées. Cela se fait en remodelant le tenseur en un vecteur 1D pour chaque échantillon dans le lot :
```python
x = x.view(-1, 64*24*24)
```
Et avec ce vecteur 1D contenant tous les paramètres d'entraînement générés par les couches convolutionnelles et de pooling précédentes, nous pouvons définir une couche entièrement connectée comme suit :
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Qui prendra la sortie aplatie de la couche précédente et la mappera à 512 unités cachées.

Notez comment cette couche a ajouté `(64 * 24 * 24 + 1 (biais)) * 512 = 3,221,504` paramètres entraînables, ce qui représente une augmentation significative par rapport aux couches convolutionnelles. Cela est dû au fait que les couches entièrement connectées relient chaque neurone d'une couche à chaque neurone de la couche suivante, entraînant un grand nombre de paramètres.

Enfin, nous pouvons ajouter une couche de sortie pour produire les logits de classe finale :
```python
self.fc2 = nn.Linear(512, num_classes)
```
Cela ajoutera `(512 + 1 (biais)) * num_classes` paramètres entraînables, où `num_classes` est le nombre de classes dans la tâche de classification (par exemple, 43 pour le jeu de données GTSRB).

Une autre pratique courante consiste à ajouter une couche de dropout avant les couches entièrement connectées pour prévenir le surapprentissage. Cela peut être fait avec :
```python
self.dropout = nn.Dropout(0.5)
```
Cette couche fixe aléatoirement une fraction des unités d'entrée à zéro pendant l'entraînement, ce qui aide à prévenir le surapprentissage en réduisant la dépendance à des neurones spécifiques.

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
### Exemple de code d'entraînement CNN

Le code suivant générera des données d'entraînement et entraînera le modèle `MY_NET` défini ci-dessus. Voici quelques valeurs intéressantes à noter :

- `EPOCHS` est le nombre de fois que le modèle verra l'ensemble du jeu de données pendant l'entraînement. Si EPOCH est trop petit, le modèle peut ne pas apprendre suffisamment ; s'il est trop grand, il peut surajuster.
- `LEARNING_RATE` est la taille du pas pour l'optimiseur. Un petit taux d'apprentissage peut conduire à une convergence lente, tandis qu'un grand peut dépasser la solution optimale et empêcher la convergence.
- `WEIGHT_DECAY` est un terme de régularisation qui aide à prévenir le surajustement en pénalisant les grands poids.

Concernant la boucle d'entraînement, voici quelques informations intéressantes à connaître :
- Le `criterion = nn.CrossEntropyLoss()` est la fonction de perte utilisée pour les tâches de classification multi-classes. Elle combine l'activation softmax et la perte d'entropie croisée en une seule fonction, ce qui la rend adaptée à l'entraînement de modèles qui produisent des logits de classe.
- Si le modèle devait produire d'autres types de sorties, comme la classification binaire ou la régression, nous utiliserions différentes fonctions de perte comme `nn.BCEWithLogitsLoss()` pour la classification binaire ou `nn.MSELoss()` pour la régression.
- Le `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` initialise l'optimiseur Adam, qui est un choix populaire pour l'entraînement de modèles d'apprentissage profond. Il adapte le taux d'apprentissage pour chaque paramètre en fonction des premiers et deuxièmes moments des gradients.
- D'autres optimisateurs comme `optim.SGD` (Stochastic Gradient Descent) ou `optim.RMSprop` pourraient également être utilisés, en fonction des exigences spécifiques de la tâche d'entraînement.
- La méthode `model.train()` met le modèle en mode entraînement, permettant aux couches comme le dropout et la normalisation par lot de se comporter différemment pendant l'entraînement par rapport à l'évaluation.
- `optimizer.zero_grad()` efface les gradients de tous les tenseurs optimisés avant le passage arrière, ce qui est nécessaire car les gradients s'accumulent par défaut dans PyTorch. S'ils ne sont pas effacés, les gradients des itérations précédentes seraient ajoutés aux gradients actuels, entraînant des mises à jour incorrectes.
- `loss.backward()` calcule les gradients de la perte par rapport aux paramètres du modèle, qui sont ensuite utilisés par l'optimiseur pour mettre à jour les poids.
- `optimizer.step()` met à jour les paramètres du modèle en fonction des gradients calculés et du taux d'apprentissage.
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
## Réseaux de Neurones Récurrents (RNN)

Les Réseaux de Neurones Récurrents (RNN) sont une classe de réseaux de neurones conçus pour traiter des données séquentielles, telles que des séries temporelles ou le langage naturel. Contrairement aux réseaux de neurones traditionnels à propagation avant, les RNN ont des connexions qui se bouclent sur elles-mêmes, leur permettant de maintenir un état caché qui capture des informations sur les entrées précédentes dans la séquence.

Les principaux composants des RNN incluent :
- **Couches Récurrentes** : Ces couches traitent les séquences d'entrée un pas de temps à la fois, mettant à jour leur état caché en fonction de l'entrée actuelle et de l'état caché précédent. Cela permet aux RNN d'apprendre des dépendances temporelles dans les données.
- **État Caché** : L'état caché est un vecteur qui résume les informations des pas de temps précédents. Il est mis à jour à chaque pas de temps et est utilisé pour faire des prédictions pour l'entrée actuelle.
- **Couche de Sortie** : La couche de sortie produit les prédictions finales en fonction de l'état caché. Dans de nombreux cas, les RNN sont utilisés pour des tâches comme la modélisation du langage, où la sortie est une distribution de probabilité sur le prochain mot dans une séquence.

Par exemple, dans un modèle de langage, le RNN traite une séquence de mots, par exemple, "Le chat s'est assis sur le" et prédit le prochain mot en fonction du contexte fourni par les mots précédents, dans ce cas, "tapis".

### Mémoire à Long Terme et Unité Récurrente Gâtée (LSTM et GRU)

Les RNN sont particulièrement efficaces pour des tâches impliquant des données séquentielles, telles que la modélisation du langage, la traduction automatique et la reconnaissance vocale. Cependant, ils peuvent avoir des difficultés avec **les dépendances à long terme en raison de problèmes comme les gradients qui disparaissent**.

Pour y remédier, des architectures spécialisées comme la Mémoire à Long Terme (LSTM) et l'Unité Récurrente Gâtée (GRU) ont été développées. Ces architectures introduisent des mécanismes de porte qui contrôlent le flux d'informations, leur permettant de capturer plus efficacement les dépendances à long terme.

- **LSTM** : Les réseaux LSTM utilisent trois portes (porte d'entrée, porte d'oubli et porte de sortie) pour réguler le flux d'informations dans et hors de l'état de cellule, leur permettant de se souvenir ou d'oublier des informations sur de longues séquences. La porte d'entrée contrôle combien de nouvelles informations ajouter en fonction de l'entrée et de l'état caché précédent, la porte d'oubli contrôle combien d'informations jeter. En combinant la porte d'entrée et la porte d'oubli, nous obtenons le nouvel état. Enfin, en combinant le nouvel état de cellule, avec l'entrée et l'état caché précédent, nous obtenons également le nouvel état caché.
- **GRU** : Les réseaux GRU simplifient l'architecture LSTM en combinant les portes d'entrée et d'oubli en une seule porte de mise à jour, les rendant computationnellement plus efficaces tout en capturant toujours les dépendances à long terme.

## LLMs (Modèles de Langage de Grande Taille)

Les Modèles de Langage de Grande Taille (LLMs) sont un type de modèle d'apprentissage profond spécifiquement conçu pour des tâches de traitement du langage naturel. Ils sont entraînés sur d'énormes quantités de données textuelles et peuvent générer du texte semblable à celui des humains, répondre à des questions, traduire des langues et effectuer diverses autres tâches liées au langage.  
Les LLMs sont généralement basés sur des architectures de transformateurs, qui utilisent des mécanismes d'auto-attention pour capturer les relations entre les mots dans une séquence, leur permettant de comprendre le contexte et de générer un texte cohérent.

### Architecture de Transformateur
L'architecture de transformateur est la base de nombreux LLMs. Elle se compose d'une structure encodeur-décodeur, où l'encodeur traite la séquence d'entrée et le décodeur génère la séquence de sortie. Les composants clés de l'architecture de transformateur incluent :
- **Mécanisme d'Auto-Attention** : Ce mécanisme permet au modèle de peser l'importance des différents mots dans une séquence lors de la génération de représentations. Il calcule des scores d'attention en fonction des relations entre les mots, permettant au modèle de se concentrer sur le contexte pertinent.
- **Attention Multi-Tête** : Ce composant permet au modèle de capturer plusieurs relations entre les mots en utilisant plusieurs têtes d'attention, chacune se concentrant sur différents aspects de l'entrée.
- **Encodage Positional** : Étant donné que les transformateurs n'ont pas de notion intégrée de l'ordre des mots, un encodage positional est ajouté aux embeddings d'entrée pour fournir des informations sur la position des mots dans la séquence.

## Modèles de Diffusion
Les modèles de diffusion sont une classe de modèles génératifs qui apprennent à générer des données en simulant un processus de diffusion. Ils sont particulièrement efficaces pour des tâches comme la génération d'images et ont gagné en popularité ces dernières années.  
Les modèles de diffusion fonctionnent en transformant progressivement une distribution de bruit simple en une distribution de données complexe à travers une série d'étapes de diffusion. Les composants clés des modèles de diffusion incluent :
- **Processus de Diffusion Avant** : Ce processus ajoute progressivement du bruit aux données, les transformant en une distribution de bruit simple. Le processus de diffusion avant est généralement défini par une série de niveaux de bruit, où chaque niveau correspond à une quantité spécifique de bruit ajoutée aux données.
- **Processus de Diffusion Inverse** : Ce processus apprend à inverser le processus de diffusion avant, débruitant progressivement les données pour générer des échantillons à partir de la distribution cible. Le processus de diffusion inverse est entraîné à l'aide d'une fonction de perte qui encourage le modèle à reconstruire les données originales à partir d'échantillons bruyants.

De plus, pour générer une image à partir d'une invite textuelle, les modèles de diffusion suivent généralement ces étapes :
1. **Encodage de Texte** : L'invite textuelle est encodée en une représentation latente à l'aide d'un encodeur de texte (par exemple, un modèle basé sur un transformateur). Cette représentation capture le sens sémantique du texte.
2. **Échantillonnage de Bruit** : Un vecteur de bruit aléatoire est échantillonné à partir d'une distribution gaussienne.
3. **Étapes de Diffusion** : Le modèle applique une série d'étapes de diffusion, transformant progressivement le vecteur de bruit en une image qui correspond à l'invite textuelle. Chaque étape implique l'application de transformations apprises pour débruiter l'image.

{{#include ../banners/hacktricks-training.md}}
