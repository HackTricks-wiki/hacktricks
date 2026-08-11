# Deep Learning

{{#include ../banners/hacktricks-training.md}}

## Deep Learning <sup>[[1]](#references)</sup>

Το deep learning είναι υποσύνολο του machine learning που χρησιμοποιεί neural networks με πολλαπλά layers (deep neural networks) για τη μοντελοποίηση σύνθετων μοτίβων σε δεδομένα. Έχει επιτύχει αξιοσημείωτα αποτελέσματα σε διάφορους τομείς, όπως computer vision, natural language processing και speech recognition.

### Neural Networks

Τα neural networks αποτελούν τα δομικά στοιχεία του deep learning. Αποτελούνται από διασυνδεδεμένους κόμβους (neurons) οργανωμένους σε layers. Κάθε neuron λαμβάνει εισόδους, εφαρμόζει ένα weighted sum και περνά το αποτέλεσμα μέσα από μια activation function για να παράγει έξοδο. Τα layers μπορούν να κατηγοριοποιηθούν ως εξής:
- **Input Layer**: Το πρώτο layer που λαμβάνει τα input δεδομένα.
- **Hidden Layers**: Ενδιάμεσα layers που εκτελούν μετασχηματισμούς στα input δεδομένα. Ο αριθμός των hidden layers και των neurons σε κάθε layer μπορεί να διαφέρει, οδηγώντας σε διαφορετικές αρχιτεκτονικές.
- **Output Layer**: Το τελικό layer που παράγει την έξοδο του network, όπως class probabilities σε εργασίες classification.


### Activation Functions

Όταν ένα layer από neurons επεξεργάζεται input δεδομένα, κάθε neuron εφαρμόζει ένα weight και ένα bias στο input (`z = w * x + b`), όπου το `w` είναι το weight, το `x` είναι το input και το `b` είναι το bias. Η έξοδος του neuron περνά στη συνέχεια μέσα από μια **activation function για την εισαγωγή μη γραμμικότητας** στο model. Αυτή η activation function υποδεικνύει ουσιαστικά αν το επόμενο neuron «θα πρέπει να ενεργοποιηθεί και σε ποιον βαθμό». Αυτό επιτρέπει στο network να μαθαίνει σύνθετα μοτίβα και σχέσεις στα δεδομένα, επιτρέποντάς του να προσεγγίζει οποιαδήποτε συνεχή συνάρτηση.

Επομένως, οι activation functions εισάγουν μη γραμμικότητα στο neural network, επιτρέποντάς του να μαθαίνει σύνθετες σχέσεις στα δεδομένα. Οι συνηθισμένες activation functions περιλαμβάνουν:
- **Sigmoid**: Αντιστοιχίζει τις input τιμές σε ένα εύρος μεταξύ 0 και 1 και χρησιμοποιείται συχνά σε binary classification.
- **ReLU (Rectified Linear Unit)**: Εξάγει απευθείας το input αν είναι θετικό· διαφορετικά, εξάγει μηδέν. Χρησιμοποιείται ευρέως λόγω της απλότητας και της αποτελεσματικότητάς της στην εκπαίδευση deep networks.
- **Tanh**: Αντιστοιχίζει τις input τιμές σε ένα εύρος μεταξύ -1 και 1 και χρησιμοποιείται συχνά σε hidden layers.
- **Softmax**: Μετατρέπει τα raw scores σε probabilities και χρησιμοποιείται συχνά στο output layer για multi-class classification.

### Backpropagation

Το backpropagation είναι ο αλγόριθμος που χρησιμοποιείται για την εκπαίδευση neural networks, προσαρμόζοντας τα weights των συνδέσεων μεταξύ των neurons. Λειτουργεί υπολογίζοντας το gradient της loss function ως προς κάθε weight και ενημερώνοντας τα weights προς την αντίθετη κατεύθυνση του gradient, ώστε να ελαχιστοποιηθεί η loss. Τα βήματα του backpropagation είναι:

1. **Forward Pass**: Υπολογισμός της εξόδου του network, περνώντας το input μέσα από τα layers και εφαρμόζοντας activation functions.
2. **Loss Calculation**: Υπολογισμός της loss (σφάλματος) μεταξύ της προβλεπόμενης εξόδου και του πραγματικού target, χρησιμοποιώντας μια loss function (π.χ. mean squared error για regression, cross-entropy για classification).
3. **Backward Pass**: Υπολογισμός των gradients της loss ως προς κάθε weight, χρησιμοποιώντας τον chain rule του λογισμού.
4. **Weight Update**: Ενημέρωση των weights με χρήση ενός optimization algorithm (π.χ. stochastic gradient descent, Adam), ώστε να ελαχιστοποιηθεί η loss.

## Convolutional Neural Networks (CNNs) <sup>[[2]](#references)</sup>

Τα Convolutional Neural Networks (CNNs) είναι ένας εξειδικευμένος τύπος neural network, σχεδιασμένος για την επεξεργασία grid-like δεδομένων, όπως images. Είναι ιδιαίτερα αποτελεσματικά σε εργασίες computer vision, χάρη στην ικανότητά τους να μαθαίνουν αυτόματα spatial hierarchies χαρακτηριστικών.

Τα κύρια components των CNNs περιλαμβάνουν:
- **Convolutional Layers**: Εφαρμόζουν convolution operations στα input δεδομένα, χρησιμοποιώντας learnable filters (kernels) για την εξαγωγή local features. Κάθε filter μετακινείται πάνω από το input και υπολογίζει ένα dot product, παράγοντας ένα feature map.
- **Pooling Layers**: Μειώνουν το μέγεθος των feature maps για να περιορίσουν τις spatial dimensions τους, διατηρώντας παράλληλα τα σημαντικά features. Οι συνηθισμένες pooling operations περιλαμβάνουν max pooling και average pooling.
- **Fully Connected Layers**: Συνδέουν κάθε neuron ενός layer με κάθε neuron του επόμενου layer, παρόμοια με τα παραδοσιακά neural networks. Αυτά τα layers χρησιμοποιούνται συνήθως στο τέλος του network για εργασίες classification.

Μέσα στα **`Convolutional Layers`** ενός CNN, μπορούμε επίσης να διακρίνουμε:
- **Initial Convolutional Layer**: Το πρώτο convolutional layer που επεξεργάζεται τα raw input δεδομένα (π.χ. μια image) και είναι χρήσιμο για τον εντοπισμό βασικών χαρακτηριστικών, όπως edges και textures.
- **Intermediate Convolutional Layers**: Τα επόμενα convolutional layers που βασίζονται στα features τα οποία μαθεύτηκαν από το initial layer, επιτρέποντας στο network να μαθαίνει πιο σύνθετα μοτίβα και αναπαραστάσεις.
- **Final Convolutional Layer**: Τα τελευταία convolutional layers πριν από τα fully connected layers, τα οποία ανιχνεύουν features υψηλού επιπέδου και προετοιμάζουν τα δεδομένα για classification.

> [!TIP]
> Τα CNNs είναι ιδιαίτερα αποτελεσματικά για εργασίες image classification, object detection και image segmentation, χάρη στην ικανότητά τους να μαθαίνουν spatial hierarchies χαρακτηριστικών σε grid-like δεδομένα και να μειώνουν τον αριθμό των parameters μέσω weight sharing.
> Επιπλέον, λειτουργούν καλύτερα με δεδομένα που υποστηρίζουν την αρχή της feature locality, όπου τα γειτονικά δεδομένα (pixels) είναι πιθανότερο να σχετίζονται μεταξύ τους απ’ ό,τι τα απομακρυσμένα pixels, κάτι που μπορεί να μην ισχύει για άλλους τύπους δεδομένων, όπως το text.
> Επιπλέον, σημειώστε ότι τα CNNs μπορούν να εντοπίζουν ακόμη και σύνθετα features, αλλά δεν μπορούν να εφαρμόσουν spatial context. Αυτό σημαίνει ότι το ίδιο feature που εντοπίζεται σε διαφορετικά σημεία της image θα θεωρείται το ίδιο.

### Example defining a CNN

*Εδώ θα βρείτε μια περιγραφή για το πώς να ορίσετε ένα Convolutional Neural Network (CNN) στο PyTorch, το οποίο ξεκινά με ένα batch από RGB images ως dataset μεγέθους 48x48 και χρησιμοποιεί convolutional layers και maxpool για την εξαγωγή features, ακολουθούμενα από fully connected layers για classification.*

Έτσι μπορείτε να ορίσετε 1 convolutional layer στο PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Αριθμός των input channels. Στην περίπτωση RGB images, είναι 3 (ένα για κάθε color channel). Αν εργάζεστε με grayscale images, θα είναι 1.

- `out_channels`: Αριθμός των output channels (filters) που θα μάθει το convolutional layer. Αυτό είναι ένα hyperparameter που μπορείτε να προσαρμόσετε ανάλογα με την αρχιτεκτονική του model σας.

- `kernel_size`: Μέγεθος του convolutional filter. Μια συνηθισμένη επιλογή είναι 3x3, που σημαίνει ότι το filter θα καλύπτει μια περιοχή 3x3 της input image. Πρόκειται για ένα colour stamp 3×3×3 που χρησιμοποιείται για την παραγωγή των out_channels από τα in_channels:
1. Τοποθετήστε αυτό το stamp 3×3×3 στην επάνω αριστερή γωνία του image cube.
2. Πολλαπλασιάστε κάθε weight με το pixel που βρίσκεται από κάτω, προσθέστε τα όλα και προσθέστε το bias → λαμβάνετε έναν αριθμό.
3. Γράψτε αυτόν τον αριθμό σε έναν κενό map στη θέση (0, 0).
4. Μετακινήστε το stamp κατά ένα pixel προς τα δεξιά (stride = 1) και επαναλάβετε μέχρι να γεμίσετε ένα πλήρες grid 48×48.

- `padding`: Αριθμός των pixels που προστίθενται σε κάθε πλευρά του input. Το padding βοηθά στη διατήρηση των spatial dimensions του input, επιτρέποντας μεγαλύτερο έλεγχο στο μέγεθος της εξόδου. Για παράδειγμα, με kernel 3x3 και input 48x48 pixels, padding ίσο με 1 θα διατηρήσει το ίδιο μέγεθος εξόδου (48x48) μετά τη convolution operation. Αυτό συμβαίνει επειδή το padding προσθέτει ένα border 1 pixel γύρω από την input image, επιτρέποντας στο kernel να μετακινείται πάνω από τις edges χωρίς να μειώνονται οι spatial dimensions.

Στη συνέχεια, ο αριθμός των trainable parameters σε αυτό το layer είναι:
- (3x3x3 (kernel size) + 1 (bias)) x 32 (out_channels) = 896 trainable parameters.

Σημειώστε ότι προστίθεται ένα Bias (+1) ανά kernel που χρησιμοποιείται, επειδή η λειτουργία κάθε convolutional layer είναι να μαθαίνει έναν linear transformation του input, ο οποίος αναπαρίσταται από την εξίσωση:
```plaintext
Y = f(W * X + b)
```
όπου το `W` είναι ο πίνακας βαρών (τα learned filters, 3x3x3 = 27 params), ενώ το `b` είναι το διάνυσμα bias, με τιμή +1 για κάθε output channel.

Σημειώστε ότι το output του `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` θα είναι ένα tensor σχήματος `(batch_size, 32, 48, 48)`, επειδή το 32 είναι ο νέος αριθμός των generated channels μεγέθους 48x48 pixels.

Στη συνέχεια, θα μπορούσαμε να συνδέσουμε αυτό το convolutional layer με ένα ακόμη convolutional layer ως εξής: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Αυτό θα προσθέσει: (32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 trainable parameters και output σχήματος `(batch_size, 64, 48, 48)`.

Όπως βλέπετε, **ο αριθμός των parameters αυξάνεται γρήγορα με κάθε επιπλέον convolutional layer**, ιδιαίτερα όσο αυξάνεται ο αριθμός των output channels.

Μια επιλογή για τον έλεγχο της ποσότητας των δεδομένων που χρησιμοποιούνται είναι η χρήση **max pooling** μετά από κάθε convolutional layer. Το max pooling μειώνει τις spatial διαστάσεις των feature maps, γεγονός που βοηθά στη μείωση του αριθμού των parameters και της υπολογιστικής πολυπλοκότητας, διατηρώντας παράλληλα τα σημαντικά features.

Μπορεί να δηλωθεί ως εξής: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Αυτό υποδεικνύει ουσιαστικά τη χρήση ενός grid 2x2 pixels και την επιλογή της μέγιστης τιμής από κάθε grid, ώστε να μειωθεί το μέγεθος του feature map στο μισό. Επιπλέον, το `stride=2` σημαίνει ότι η pooling operation θα μετακινείται κατά 2 pixels κάθε φορά, αποτρέποντας σε αυτή την περίπτωση οποιαδήποτε επικάλυψη μεταξύ των pooling regions.

Με αυτό το pooling layer, το output shape μετά το πρώτο convolutional layer θα ήταν `(batch_size, 64, 24, 24)` αφού εφαρμοστεί το `self.pool1` στο output του `self.conv2`, μειώνοντας το μέγεθος στο 1/4 του προηγούμενου layer.

> [!TIP]
> Είναι σημαντικό να εφαρμόζετε pooling μετά τα convolutional layers, ώστε να μειώνονται οι spatial διαστάσεις των feature maps. Αυτό βοηθά στον έλεγχο του αριθμού των parameters και της υπολογιστικής πολυπλοκότητας, ενώ επιτρέπει στην αρχική παράμετρο να μάθει σημαντικά features.
>You can see the convolutions before a pooling layer as a way to extract features from the input data (like lines, edges), this information will still be present in the pooled output, but the next convolutional layer will not be able to see the original input data, only the pooled output, which is a reduced version of the previous layer with that information.
>In the usual order: `Conv → ReLU → Pool` each 2×2 pooling window now contends with feature activations (“edge present / not”), not raw pixel intensities. Keeping the strongest activation really does keep the most salient evidence.

Στη συνέχεια, αφού προσθέσουμε όσα convolutional και pooling layers χρειάζονται, μπορούμε να κάνουμε flatten το output, ώστε να το τροφοδοτήσουμε σε fully connected layers. Αυτό γίνεται με την αλλαγή σχήματος του tensor σε ένα 1D vector για κάθε sample του batch:
```python
x = x.view(-1, 64*24*24)
```
Και με αυτό το 1D διάνυσμα, που περιέχει όλες τις παραμέτρους εκπαίδευσης οι οποίες δημιουργήθηκαν από τα προηγούμενα convolutional και pooling layers, μπορούμε να ορίσουμε ένα fully connected layer όπως:
```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```
Το οποίο θα λάβει την ισοπεδωμένη έξοδο του προηγούμενου layer και θα τη χαρτογραφήσει σε 512 hidden units.

Σημειώστε ότι αυτό το layer πρόσθεσε `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` trainable parameters, το οποίο αποτελεί σημαντική αύξηση σε σύγκριση με τα convolutional layers. Αυτό συμβαίνει επειδή τα fully connected layers συνδέουν κάθε neuron ενός layer με κάθε neuron του επόμενου layer, οδηγώντας σε μεγάλο αριθμό parameters.

Τέλος, μπορούμε να προσθέσουμε ένα output layer για την παραγωγή των τελικών class logits:
```python
self.fc2 = nn.Linear(512, num_classes)
```
Αυτό θα προσθέσει `(512 + 1 (bias)) * num_classes` trainable parameters, όπου το `num_classes` είναι ο αριθμός των classes στην εργασία classification (π.χ. 43 για το dataset GTSRB).

Μια τελευταία συνηθισμένη πρακτική είναι να προσθέσετε ένα dropout layer πριν από τα fully connected layers, για την αποφυγή του overfitting. Αυτό μπορεί να γίνει με:
```python
self.dropout = nn.Dropout(0.5)
```
Αυτό το επίπεδο μηδενίζει τυχαία ένα μέρος των μονάδων εισόδου κατά την εκπαίδευση, γεγονός που συμβάλλει στην αποτροπή του overfitting μειώνοντας την εξάρτηση από συγκεκριμένους νευρώνες.

### Παράδειγμα κώδικα CNN
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

Ο ακόλουθος κώδικας θα δημιουργήσει training data και θα εκπαιδεύσει το μοντέλο `MY_NET` που ορίστηκε παραπάνω. Μερικές ενδιαφέρουσες τιμές που αξίζει να σημειωθούν:

- Το `EPOCHS` είναι ο αριθμός των φορών που το μοντέλο θα δει ολόκληρο το dataset κατά την εκπαίδευση. Αν το EPOCH είναι πολύ μικρό, το μοντέλο ενδέχεται να μην μάθει αρκετά· αν είναι πολύ μεγάλο, μπορεί να προκύψει overfitting.
- Το `LEARNING_RATE` είναι το μέγεθος βήματος για τον optimizer. Ένα μικρό learning rate μπορεί να οδηγήσει σε αργή σύγκλιση, ενώ ένα μεγάλο μπορεί να ξεπεράσει τη βέλτιστη λύση και να αποτρέψει τη σύγκλιση.
- Το `WEIGHT_DECAY` είναι ένας όρος regularization που βοηθά στην αποτροπή του overfitting, penalizing τα μεγάλα βάρη.

Όσον αφορά το training loop, ακολουθούν ορισμένες ενδιαφέρουσες πληροφορίες:
- Το `criterion = nn.CrossEntropyLoss()` είναι η loss function που χρησιμοποιείται για multi-class classification tasks. Συνδυάζει softmax activation και cross-entropy loss σε μία συνάρτηση, γεγονός που την καθιστά κατάλληλη για την εκπαίδευση μοντέλων που παράγουν class logits.
- Αν το μοντέλο αναμενόταν να παράγει άλλους τύπους outputs, όπως binary classification ή regression, θα χρησιμοποιούσαμε διαφορετικές loss functions, όπως `nn.BCEWithLogitsLoss()` για binary classification ή `nn.MSELoss()` για regression.
- Το `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` αρχικοποιεί τον Adam optimizer, ο οποίος αποτελεί δημοφιλή επιλογή για την εκπαίδευση deep learning models. Προσαρμόζει το learning rate για κάθε parameter με βάση την πρώτη και τη δεύτερη ροπή των gradients.
- Θα μπορούσαν επίσης να χρησιμοποιηθούν άλλοι optimizers, όπως `optim.SGD` (Stochastic Gradient Descent) ή `optim.RMSprop`, ανάλογα με τις συγκεκριμένες απαιτήσεις του training task.
- Η μέθοδος `model.train()` θέτει το μοντέλο σε training mode, επιτρέποντας σε layers όπως τα dropout και batch normalization να συμπεριφέρονται διαφορετικά κατά την εκπαίδευση σε σχέση με το evaluation.
- Η `optimizer.zero_grad()` διαγράφει τα gradients όλων των optimized tensors πριν από το backward pass, κάτι που είναι απαραίτητο επειδή τα gradients συσσωρεύονται από προεπιλογή στο PyTorch. Αν δεν διαγραφούν, τα gradients από προηγούμενες iterations θα προστίθενταν στα τρέχοντα gradients, οδηγώντας σε εσφαλμένες updates.
- Η `loss.backward()` υπολογίζει τα gradients της loss ως προς τα model parameters, τα οποία στη συνέχεια χρησιμοποιούνται από τον optimizer για την ενημέρωση των weights.
- Η `optimizer.step()` ενημερώνει τα model parameters με βάση τα υπολογισμένα gradients και το learning rate.
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
## Επαναλαμβανόμενα Νευρωνικά Δίκτυα (RNNs) <sup>[[3]](#references)</sup>

Τα Επαναλαμβανόμενα Νευρωνικά Δίκτυα (RNNs) είναι μια κατηγορία νευρωνικών δικτύων σχεδιασμένων για την επεξεργασία διαδοχικών δεδομένων, όπως χρονοσειρές ή φυσική γλώσσα. Σε αντίθεση με τα παραδοσιακά νευρωνικά δίκτυα feedforward, τα RNNs διαθέτουν συνδέσεις που επιστρέφουν στον εαυτό τους, επιτρέποντάς τους να διατηρούν μια κρυφή κατάσταση που καταγράφει πληροφορίες σχετικά με προηγούμενες εισόδους της ακολουθίας.

Τα κύρια στοιχεία των RNNs περιλαμβάνουν:
- **Επαναλαμβανόμενα Επίπεδα**: Αυτά τα επίπεδα επεξεργάζονται τις ακολουθίες εισόδου ένα χρονικό βήμα κάθε φορά, ενημερώνοντας την κρυφή τους κατάσταση με βάση την τρέχουσα είσοδο και την προηγούμενη κρυφή κατάσταση. Αυτό επιτρέπει στα RNNs να μαθαίνουν χρονικές εξαρτήσεις στα δεδομένα.
- **Κρυφή Κατάσταση**: Η κρυφή κατάσταση είναι ένα διάνυσμα που συνοψίζει τις πληροφορίες από προηγούμενα χρονικά βήματα. Ενημερώνεται σε κάθε χρονικό βήμα και χρησιμοποιείται για την πραγματοποίηση προβλέψεων σχετικά με την τρέχουσα είσοδο.
- **Επίπεδο Εξόδου**: Το επίπεδο εξόδου παράγει τις τελικές προβλέψεις με βάση την κρυφή κατάσταση. Σε πολλές περιπτώσεις, τα RNNs χρησιμοποιούνται για εργασίες όπως η μοντελοποίηση γλώσσας, όπου η έξοδος είναι μια κατανομή πιθανοτήτων πάνω στην επόμενη λέξη μιας ακολουθίας.

Για παράδειγμα, σε ένα μοντέλο γλώσσας, το RNN επεξεργάζεται μια ακολουθία λέξεων, για παράδειγμα, "The cat sat on the" και προβλέπει την επόμενη λέξη με βάση το πλαίσιο που παρέχουν οι προηγούμενες λέξεις, σε αυτή την περίπτωση, "mat".

### Long Short-Term Memory (LSTM) και Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

Τα RNNs είναι ιδιαίτερα αποτελεσματικά για εργασίες που περιλαμβάνουν διαδοχικά δεδομένα, όπως η μοντελοποίηση γλώσσας, η αυτόματη μετάφραση και η αναγνώριση ομιλίας. Ωστόσο, μπορεί να δυσκολεύονται με **εξαρτήσεις μεγάλης εμβέλειας λόγω προβλημάτων όπως τα gradients που εξαφανίζονται**.

Για την αντιμετώπιση αυτού του προβλήματος, αναπτύχθηκαν εξειδικευμένες αρχιτεκτονικές όπως τα Long Short-Term Memory (LSTM) και Gated Recurrent Unit (GRU). Αυτές οι αρχιτεκτονικές εισάγουν μηχανισμούς πυλών που ελέγχουν τη ροή των πληροφοριών, επιτρέποντάς τους να καταγράφουν αποτελεσματικότερα εξαρτήσεις μεγάλης εμβέλειας.

- **LSTM**: Τα δίκτυα LSTM χρησιμοποιούν τρεις πύλες (πύλη εισόδου, πύλη λήθης και πύλη εξόδου) για να ρυθμίζουν τη ροή των πληροφοριών προς και από την κατάσταση του cell, επιτρέποντάς τους να θυμούνται ή να ξεχνούν πληροφορίες σε μεγάλες ακολουθίες. Η πύλη εισόδου ελέγχει πόσες νέες πληροφορίες θα προστεθούν με βάση την είσοδο και την προηγούμενη κρυφή κατάσταση, ενώ η πύλη λήθης ελέγχει πόσες πληροφορίες θα απορριφθούν. Συνδυάζοντας την πύλη εισόδου και την πύλη λήθης, λαμβάνουμε τη νέα κατάσταση. Τέλος, συνδυάζοντας τη νέα κατάσταση του cell με την είσοδο και την προηγούμενη κρυφή κατάσταση, λαμβάνουμε επίσης τη νέα κρυφή κατάσταση.
- **GRU**: Τα δίκτυα GRU απλοποιούν την αρχιτεκτονική LSTM συνδυάζοντας τις πύλες εισόδου και λήθης σε μία ενιαία πύλη ενημέρωσης, καθιστώντας τα υπολογιστικά αποδοτικότερα, ενώ εξακολουθούν να καταγράφουν εξαρτήσεις μεγάλης εμβέλειας.

## LLMs (Μεγάλα Γλωσσικά Μοντέλα)

Τα Μεγάλα Γλωσσικά Μοντέλα (LLMs) είναι ένας τύπος μοντέλου deep learning, σχεδιασμένος ειδικά για εργασίες επεξεργασίας φυσικής γλώσσας. Εκπαιδεύονται σε τεράστιες ποσότητες δεδομένων κειμένου και μπορούν να δημιουργούν κείμενο που μοιάζει με ανθρώπινο, να απαντούν σε ερωτήσεις, να μεταφράζουν γλώσσες και να εκτελούν διάφορες άλλες εργασίες που σχετίζονται με τη γλώσσα.
Τα LLMs βασίζονται συνήθως σε αρχιτεκτονικές transformer, οι οποίες χρησιμοποιούν μηχανισμούς self-attention για να καταγράφουν τις σχέσεις μεταξύ των λέξεων μιας ακολουθίας, επιτρέποντάς τους να κατανοούν το πλαίσιο και να δημιουργούν συνεκτικό κείμενο.

### Αρχιτεκτονική Transformer <sup>[[4]](#references)</sup>
Η αρχιτεκτονική transformer αποτελεί τη βάση πολλών LLMs. Αποτελείται από μια δομή encoder-decoder, όπου ο encoder επεξεργάζεται την ακολουθία εισόδου και ο decoder δημιουργεί την ακολουθία εξόδου. Τα βασικά στοιχεία της αρχιτεκτονικής transformer περιλαμβάνουν:
- **Μηχανισμός Self-Attention**: Αυτός ο μηχανισμός επιτρέπει στο μοντέλο να σταθμίζει τη σημασία διαφορετικών λέξεων σε μια ακολουθία κατά τη δημιουργία αναπαραστάσεων. Υπολογίζει scores attention με βάση τις σχέσεις μεταξύ των λέξεων, επιτρέποντας στο μοντέλο να εστιάζει στο σχετικό πλαίσιο.
- **Multi-Head Attention**: Αυτό το στοιχείο επιτρέπει στο μοντέλο να καταγράφει πολλαπλές σχέσεις μεταξύ των λέξεων χρησιμοποιώντας πολλαπλές κεφαλές attention, καθεμία από τις οποίες εστιάζει σε διαφορετικές πτυχές της εισόδου.
- **Positional Encoding**: Επειδή οι transformers δεν διαθέτουν ενσωματωμένη αντίληψη της σειράς των λέξεων, προστίθεται positional encoding στα embeddings εισόδου ώστε να παρέχονται πληροφορίες σχετικά με τη θέση των λέξεων στην ακολουθία.

## Μοντέλα Diffusion <sup>[[5]](#references)</sup>
Τα μοντέλα diffusion είναι μια κατηγορία generative μοντέλων που μαθαίνουν να δημιουργούν δεδομένα προσομοιώνοντας μια διαδικασία diffusion. Είναι ιδιαίτερα αποτελεσματικά για εργασίες όπως η δημιουργία εικόνων και έχουν γίνει δημοφιλή τα τελευταία χρόνια.
Τα μοντέλα diffusion λειτουργούν μετασχηματίζοντας σταδιακά μια απλή κατανομή θορύβου σε μια σύνθετη κατανομή δεδομένων μέσω μιας σειράς βημάτων diffusion. Τα βασικά στοιχεία των μοντέλων diffusion περιλαμβάνουν:
- **Διαδικασία Forward Diffusion**: Αυτή η διαδικασία προσθέτει σταδιακά θόρυβο στα δεδομένα, μετασχηματίζοντάς τα σε μια απλή κατανομή θορύβου. Η διαδικασία forward diffusion ορίζεται συνήθως από μια σειρά επιπέδων θορύβου, όπου κάθε επίπεδο αντιστοιχεί σε συγκεκριμένη ποσότητα θορύβου που προστίθεται στα δεδομένα.
- **Διαδικασία Reverse Diffusion**: Αυτή η διαδικασία μαθαίνει να αντιστρέφει τη διαδικασία forward diffusion, αποθορυβοποιώντας σταδιακά τα δεδομένα για να δημιουργήσει δείγματα από την κατανομή-στόχο. Η διαδικασία reverse diffusion εκπαιδεύεται χρησιμοποιώντας μια συνάρτηση loss που ενθαρρύνει το μοντέλο να ανακατασκευάζει τα αρχικά δεδομένα από θορυβώδη δείγματα.

Επιπλέον, για να δημιουργήσουν μια εικόνα από ένα prompt κειμένου, τα μοντέλα diffusion ακολουθούν συνήθως τα εξής βήματα:
1. **Κωδικοποίηση Κειμένου**: Το prompt κειμένου κωδικοποιείται σε μια λανθάνουσα αναπαράσταση χρησιμοποιώντας έναν text encoder (π.χ. ένα μοντέλο βασισμένο σε transformer). Αυτή η αναπαράσταση καταγράφει τη σημασιολογική σημασία του κειμένου.
2. **Δειγματοληψία Θορύβου**: Γίνεται δειγματοληψία ενός τυχαίου διανύσματος θορύβου από μια Gaussian κατανομή.
3. **Βήματα Diffusion**: Το μοντέλο εφαρμόζει μια σειρά βημάτων diffusion, μετασχηματίζοντας σταδιακά το διάνυσμα θορύβου σε μια εικόνα που αντιστοιχεί στο prompt κειμένου. Κάθε βήμα περιλαμβάνει την εφαρμογή μαθημένων μετασχηματισμών για την αποθορυβοποίηση της εικόνας.

## References

- [1] [PyTorch - Εκμάθηση Νευρωνικών Δικτύων](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Μοντέλα Πιθανοτικής Diffusion με Αποθορυβοποίηση](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
