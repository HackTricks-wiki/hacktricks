# Học sâu

{{#include ../banners/hacktricks-training.md}}

## Học sâu <sup>[[1]](#references)</sup>

Học sâu là một nhánh của machine learning sử dụng mạng neural nhiều lớp (mạng neural sâu) để mô hình hóa các mẫu phức tạp trong dữ liệu. Phương pháp này đã đạt được thành công đáng kể trong nhiều lĩnh vực, bao gồm thị giác máy tính, xử lý ngôn ngữ tự nhiên và nhận dạng giọng nói.

### Mạng neural

Mạng neural là nền tảng của học sâu. Chúng gồm các nút liên kết với nhau (neuron), được tổ chức thành các lớp. Mỗi neuron nhận đầu vào, tính tổng có trọng số rồi đưa kết quả qua hàm kích hoạt để tạo đầu ra. Các lớp có thể được chia thành:
- **Lớp đầu vào**: Lớp đầu tiên nhận dữ liệu đầu vào.
- **Lớp ẩn**: Các lớp trung gian thực hiện biến đổi dữ liệu đầu vào. Số lượng lớp ẩn và neuron trong mỗi lớp có thể thay đổi, tạo nên các kiến trúc khác nhau.
- **Lớp đầu ra**: Lớp cuối cùng tạo đầu ra của mạng, chẳng hạn như xác suất của các lớp trong tác vụ phân loại.


### Hàm kích hoạt

Khi một lớp neuron xử lý dữ liệu đầu vào, mỗi neuron áp dụng trọng số và độ lệch cho dữ liệu đầu vào (`z = w * x + b`), trong đó `w` là trọng số, `x` là đầu vào và `b` là độ lệch. Sau đó, đầu ra của neuron được đưa qua **hàm kích hoạt để tạo tính phi tuyến** cho mô hình. Về cơ bản, hàm kích hoạt cho biết neuron tiếp theo "có nên được kích hoạt hay không và ở mức độ nào". Nhờ đó, mạng có thể học các mẫu và mối quan hệ phức tạp trong dữ liệu, cho phép mạng xấp xỉ mọi hàm liên tục.

Vì vậy, các hàm kích hoạt tạo tính phi tuyến cho mạng neural, cho phép mạng học các mối quan hệ phức tạp trong dữ liệu. Các hàm kích hoạt phổ biến gồm:
- **Sigmoid**: Ánh xạ giá trị đầu vào vào khoảng từ 0 đến 1, thường dùng trong phân loại nhị phân.
- **ReLU (Rectified Linear Unit)**: Trả về trực tiếp giá trị đầu vào nếu giá trị đó dương; nếu không, trả về 0. Hàm này được sử dụng rộng rãi nhờ tính đơn giản và hiệu quả khi huấn luyện mạng sâu.
- **Tanh**: Ánh xạ giá trị đầu vào vào khoảng từ -1 đến 1, thường dùng trong các lớp ẩn.
- **Softmax**: Chuyển điểm số thô thành xác suất, thường dùng ở lớp đầu ra cho tác vụ phân loại nhiều lớp.

### Lan truyền ngược

Lan truyền ngược là thuật toán dùng để huấn luyện mạng neural bằng cách điều chỉnh trọng số của các kết nối giữa các neuron. Thuật toán tính gradient của hàm mất mát theo từng trọng số, sau đó cập nhật trọng số theo hướng ngược với gradient để giảm thiểu mất mát. Các bước trong quá trình lan truyền ngược gồm:

1. **Lan truyền thuận**: Tính đầu ra của mạng bằng cách đưa đầu vào qua các lớp và áp dụng các hàm kích hoạt.
2. **Tính toán mất mát**: Tính mất mát (sai số) giữa đầu ra dự đoán và mục tiêu thực tế bằng hàm mất mát (ví dụ: sai số bình phương trung bình cho hồi quy, cross-entropy cho phân loại).
3. **Lan truyền ngược**: Tính gradient của mất mát theo từng trọng số bằng quy tắc dây chuyền trong giải tích.
4. **Cập nhật trọng số**: Cập nhật trọng số bằng thuật toán tối ưu hóa (ví dụ: stochastic gradient descent, Adam) để giảm thiểu mất mát.

## Mạng neural tích chập (CNN) <sup>[[2]](#references)</sup>

Mạng neural tích chập (CNN) là một loại mạng neural chuyên biệt, được thiết kế để xử lý dữ liệu dạng lưới như hình ảnh. CNN đặc biệt hiệu quả trong các tác vụ thị giác máy tính nhờ khả năng tự động học các hệ phân cấp đặc trưng không gian.

Các thành phần chính của CNN gồm:
- **Lớp tích chập**: Áp dụng phép tích chập lên dữ liệu đầu vào bằng các bộ lọc có thể học được (kernel) để trích xuất đặc trưng cục bộ. Mỗi bộ lọc trượt qua dữ liệu đầu vào và tính tích vô hướng, tạo ra một bản đồ đặc trưng.
- **Lớp pooling**: Giảm kích thước không gian của các bản đồ đặc trưng trong khi vẫn giữ lại những đặc trưng quan trọng. Các phép pooling phổ biến gồm max pooling và average pooling.
- **Lớp kết nối đầy đủ**: Kết nối mọi neuron trong một lớp với mọi neuron trong lớp tiếp theo, tương tự mạng neural truyền thống. Các lớp này thường được dùng ở cuối mạng cho các tác vụ phân loại.

Trong **`Lớp tích chập`** của CNN, ta cũng có thể phân biệt:
- **Lớp tích chập ban đầu**: Lớp tích chập đầu tiên xử lý dữ liệu đầu vào thô (ví dụ: hình ảnh) và giúp nhận diện các đặc trưng cơ bản như cạnh và kết cấu.
- **Các lớp tích chập trung gian**: Các lớp tích chập tiếp theo xây dựng dựa trên những đặc trưng mà lớp ban đầu đã học, cho phép mạng học các mẫu và biểu diễn phức tạp hơn.
- **Lớp tích chập cuối cùng**: Các lớp tích chập cuối trước các lớp kết nối đầy đủ, nắm bắt đặc trưng cấp cao và chuẩn bị dữ liệu cho việc phân loại.

> [!TIP]
> CNN đặc biệt hiệu quả trong các tác vụ phân loại hình ảnh, phát hiện vật thể và phân đoạn hình ảnh nhờ khả năng học các hệ phân cấp đặc trưng trong dữ liệu dạng lưới và giảm số lượng tham số thông qua chia sẻ trọng số.
> Ngoài ra, CNN hoạt động tốt hơn với dữ liệu tuân theo nguyên tắc tính cục bộ của đặc trưng, theo đó các dữ liệu (pixel) lân cận có nhiều khả năng liên quan với nhau hơn các pixel ở xa; điều này có thể không đúng với các loại dữ liệu khác như văn bản.
> Hơn nữa, hãy lưu ý rằng CNN có thể nhận diện cả những đặc trưng phức tạp nhưng không thể áp dụng ngữ cảnh không gian, nghĩa là cùng một đặc trưng được tìm thấy ở các vị trí khác nhau trong ảnh vẫn được xem là như nhau.

### Ví dụ định nghĩa một CNN

*Ở đây bạn sẽ tìm thấy mô tả cách định nghĩa Mạng neural tích chập (CNN) trong PyTorch. Mạng này nhận một batch ảnh RGB có kích thước 48x48 làm dataset, sử dụng các lớp tích chập và maxpool để trích xuất đặc trưng, sau đó dùng các lớp kết nối đầy đủ để phân loại.*

Sau đây là cách định nghĩa 1 lớp tích chập trong PyTorch: `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)`.

- `in_channels`: Số lượng kênh đầu vào. Với ảnh RGB, giá trị này là 3 (mỗi kênh màu một kênh). Nếu làm việc với ảnh grayscale, giá trị này là 1.

- `out_channels`: Số lượng kênh đầu ra (bộ lọc) mà lớp tích chập sẽ học. Đây là một hyperparameter mà bạn có thể điều chỉnh tùy theo kiến trúc mô hình.

- `kernel_size`: Kích thước của bộ lọc tích chập. Lựa chọn phổ biến là 3x3, nghĩa là bộ lọc sẽ bao phủ một vùng 3x3 của ảnh đầu vào. Bộ lọc này giống như một con dấu màu 3×3×3 được dùng để tạo ra out_channels từ in_channels:
  1. Đặt con dấu 3×3×3 đó lên góc trên bên trái của khối ảnh.
  2. Nhân từng trọng số với pixel nằm bên dưới, cộng tất cả lại rồi cộng độ lệch → bạn nhận được một số.
  3. Ghi số đó vào bản đồ trống tại vị trí (0, 0).
  4. Trượt con dấu sang phải một pixel (stride = 1) rồi lặp lại cho đến khi lấp đầy toàn bộ lưới 48×48.

- `padding`: Số pixel được thêm vào mỗi cạnh của đầu vào. Padding giúp giữ nguyên kích thước không gian của đầu vào, cho phép kiểm soát kích thước đầu ra tốt hơn. Ví dụ: với kernel 3x3 và đầu vào 48x48 pixel, padding bằng 1 sẽ giữ nguyên kích thước đầu ra (48x48) sau phép tích chập. Đó là vì padding thêm một đường viền rộng 1 pixel quanh ảnh đầu vào, cho phép kernel trượt qua các cạnh mà không làm giảm kích thước không gian.

Khi đó, số tham số có thể huấn luyện trong lớp này là:
- (3x3x3 (kích thước kernel) + 1 (độ lệch)) x 32 (out_channels) = 896 tham số có thể huấn luyện.

Lưu ý rằng một Bias (+1) được thêm cho mỗi kernel được sử dụng, vì chức năng của mỗi lớp tích chập là học phép biến đổi tuyến tính của đầu vào, được biểu diễn bằng phương trình:

```plaintext
Y = f(W * X + b)
```

trong đó `W` là ma trận trọng số (các filter đã học, 3x3x3 = 27 tham số), `b` là vector bias có giá trị +1 cho mỗi kênh đầu ra.

Lưu ý rằng đầu ra của `self.conv1 = nn.Conv2d(in_channels=3, out_channels=32, kernel_size=3, padding=1)` sẽ là tensor có shape `(batch_size, 32, 48, 48)`, vì 32 là số kênh mới được tạo, mỗi kênh có kích thước 48x48 pixel.

Sau đó, ta có thể nối lớp convolution này với một lớp convolution khác như sau: `self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=3, padding=1)`.

Lớp này sẽ thêm: (32x3x3 (kernel size) + 1 (bias)) x 64 (out_channels) = 18,496 tham số có thể huấn luyện và tạo đầu ra có shape `(batch_size, 64, 48, 48)`.

Như bạn thấy, **số lượng tham số tăng nhanh theo mỗi lớp convolution được thêm vào**, đặc biệt khi số kênh đầu ra tăng.

Một cách để kiểm soát lượng dữ liệu được sử dụng là dùng **max pooling** sau mỗi lớp convolution. Max pooling giảm kích thước không gian của các feature map, giúp giảm số lượng tham số và độ phức tạp tính toán trong khi vẫn giữ lại các đặc trưng quan trọng.

Có thể khai báo như sau: `self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)`. Về cơ bản, cấu hình này dùng một lưới gồm 2x2 pixel và lấy giá trị lớn nhất trong mỗi lưới để giảm một nửa kích thước của feature map. Ngoài ra, `stride=2` nghĩa là thao tác pooling sẽ dịch chuyển mỗi lần 2 pixel; trong trường hợp này, các vùng pooling sẽ không chồng lấp nhau.

Với lớp pooling này, shape đầu ra sau lớp convolution đầu tiên sẽ là `(batch_size, 64, 24, 24)` sau khi áp dụng `self.pool1` lên đầu ra của `self.conv2`, giảm kích thước xuống còn 1/4 so với lớp trước đó.

> [!TIP]
> Điều quan trọng là thực hiện pooling sau các lớp convolution để giảm kích thước không gian của các feature map. Việc này giúp kiểm soát số lượng tham số và độ phức tạp tính toán, đồng thời giúp các tham số ban đầu học được những đặc trưng quan trọng.
>Bạn có thể xem các phép convolution trước một lớp pooling như cách trích xuất đặc trưng từ dữ liệu đầu vào (chẳng hạn như đường thẳng, cạnh). Thông tin này vẫn hiện diện trong đầu ra đã pooling, nhưng lớp convolution tiếp theo sẽ không thể thấy dữ liệu đầu vào ban đầu mà chỉ thấy đầu ra đã pooling — phiên bản rút gọn của lớp trước đó nhưng vẫn chứa thông tin ấy.
>Theo thứ tự thường dùng: `Conv → ReLU → Pool`, mỗi cửa sổ pooling 2×2 lúc này xử lý các giá trị kích hoạt đặc trưng (“có cạnh / không có cạnh”), thay vì cường độ pixel thô. Việc giữ lại giá trị kích hoạt mạnh nhất thực sự giúp giữ lại bằng chứng nổi bật nhất.

Sau khi thêm số lớp convolution và pooling cần thiết, ta có thể làm phẳng đầu ra để đưa vào các lớp fully connected. Việc này được thực hiện bằng cách reshape tensor thành một vector 1D cho mỗi mẫu trong batch:

```python
x = x.view(-1, 64*24*24)
```

Và với vector 1D này chứa tất cả các tham số huấn luyện được tạo ra bởi các lớp convolutional và pooling trước đó, chúng ta có thể định nghĩa một lớp fully connected như sau:

```python
self.fc1 = nn.Linear(64 * 24 * 24, 512)
```

Lớp này sẽ nhận đầu ra đã được làm phẳng của lớp trước và ánh xạ nó thành 512 đơn vị ẩn.

Lưu ý rằng lớp này đã thêm `(64 * 24 * 24 + 1 (bias)) * 512 = 3,221,504` tham số có thể huấn luyện, tăng đáng kể so với các lớp tích chập. Đó là vì các lớp fully connected kết nối mọi neuron của lớp này với mọi neuron của lớp tiếp theo, dẫn đến số lượng tham số lớn.

Cuối cùng, chúng ta có thể thêm một lớp đầu ra để tạo ra các logits của lớp cuối cùng:

```python
self.fc2 = nn.Linear(512, num_classes)
```

Điều này sẽ thêm `(512 + 1 (bias)) * num_classes` tham số có thể huấn luyện, trong đó `num_classes` là số lớp trong tác vụ phân loại (ví dụ: 43 với dataset GTSRB).

Một thực hành phổ biến khác là thêm một lớp dropout trước các lớp fully connected để ngăn overfitting. Có thể thực hiện như sau:

```python
self.dropout = nn.Dropout(0.5)
```
Lớp này ngẫu nhiên đặt một phần các đơn vị đầu vào thành 0 trong quá trình huấn luyện, giúp ngăn overfitting bằng cách giảm sự phụ thuộc vào các neuron cụ thể.

### Ví dụ mã CNN

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

### Ví dụ huấn luyện bằng code CNN

Đoạn code sau sẽ tạo một số dữ liệu huấn luyện và huấn luyện model `MY_NET` được định nghĩa ở trên. Một số giá trị đáng chú ý:

- `EPOCHS` là số lần model sẽ xử lý toàn bộ dataset trong quá trình huấn luyện. Nếu EPOCH quá nhỏ, model có thể chưa học đủ; nếu quá lớn, model có thể bị quá khớp.
- `LEARNING_RATE` là kích thước bước của optimizer. Learning rate nhỏ có thể khiến quá trình hội tụ chậm, còn learning rate lớn có thể vượt quá nghiệm tối ưu và khiến model không hội tụ.
- `WEIGHT_DECAY` là một thành phần regularization giúp ngăn quá khớp bằng cách phạt các trọng số lớn.

Một số thông tin đáng chú ý về vòng lặp huấn luyện:
- `criterion = nn.CrossEntropyLoss()` là hàm loss dùng cho các tác vụ phân loại nhiều lớp. Hàm này kết hợp softmax activation và cross-entropy loss, phù hợp để huấn luyện các model tạo ra logits của lớp.
    - Nếu model cần tạo ra các kiểu đầu ra khác, chẳng hạn như phân loại nhị phân hoặc hồi quy, ta sẽ dùng các hàm loss khác, chẳng hạn `nn.BCEWithLogitsLoss()` cho phân loại nhị phân hoặc `nn.MSELoss()` cho hồi quy.
- `optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)` khởi tạo Adam optimizer, một lựa chọn phổ biến để huấn luyện các model deep learning. Optimizer này điều chỉnh learning rate cho từng tham số dựa trên moment bậc nhất và bậc hai của gradient.
    - Các optimizer khác như `optim.SGD` (Stochastic Gradient Descent) hoặc `optim.RMSprop` cũng có thể được sử dụng, tùy theo yêu cầu cụ thể của tác vụ huấn luyện.
- Phương thức `model.train()` chuyển model sang chế độ huấn luyện, cho phép các layer như dropout và batch normalization hoạt động khác với khi đánh giá model.
- `optimizer.zero_grad()` xóa gradient của tất cả tensor được tối ưu hóa trước lượt lan truyền ngược. Việc này cần thiết vì gradient mặc định được tích lũy trong PyTorch. Nếu không xóa, gradient từ các lượt lặp trước sẽ được cộng vào gradient hiện tại, dẫn đến các lần cập nhật không chính xác.
- `loss.backward()` tính gradient của loss theo các tham số của model; optimizer sẽ dùng các gradient này để cập nhật trọng số.
- `optimizer.step()` cập nhật các tham số của model dựa trên gradient đã tính và learning rate.

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

Recurrent Neural Networks (RNNs) là một lớp mạng neural được thiết kế để xử lý dữ liệu tuần tự, chẳng hạn như chuỗi thời gian hoặc ngôn ngữ tự nhiên. Không giống các mạng neural feedforward truyền thống, RNN có các kết nối vòng lặp lại chính chúng, cho phép duy trì một trạng thái ẩn lưu giữ thông tin về các đầu vào trước đó trong chuỗi.

Các thành phần chính của RNN gồm:
- **Recurrent Layers**: Các layer này xử lý chuỗi đầu vào từng bước thời gian, cập nhật trạng thái ẩn dựa trên đầu vào hiện tại và trạng thái ẩn trước đó. Điều này cho phép RNN học các phụ thuộc theo thời gian trong dữ liệu.
- **Hidden State**: Trạng thái ẩn là một vector tóm tắt thông tin từ các bước thời gian trước đó. Trạng thái này được cập nhật ở mỗi bước thời gian và được dùng để đưa ra dự đoán cho đầu vào hiện tại.
- **Output Layer**: Output layer tạo ra các dự đoán cuối cùng dựa trên trạng thái ẩn. Trong nhiều trường hợp, RNN được dùng cho các tác vụ như mô hình hóa ngôn ngữ, trong đó đầu ra là phân phối xác suất trên từ tiếp theo trong chuỗi.

Ví dụ, trong một mô hình ngôn ngữ, RNN xử lý một chuỗi từ, chẳng hạn "The cat sat on the", rồi dự đoán từ tiếp theo dựa trên ngữ cảnh do các từ trước đó cung cấp; trong trường hợp này là "mat".

### Long Short-Term Memory (LSTM) and Gated Recurrent Unit (GRU) <sup>[[3]](#references)</sup>

RNN đặc biệt hiệu quả với các tác vụ liên quan đến dữ liệu tuần tự, chẳng hạn như mô hình hóa ngôn ngữ, dịch máy và nhận dạng giọng nói. Tuy nhiên, chúng có thể gặp khó khăn với **các phụ thuộc tầm xa do những vấn đề như vanishing gradients**.

Để khắc phục vấn đề này, các kiến trúc chuyên biệt như Long Short-Term Memory (LSTM) và Gated Recurrent Unit (GRU) đã được phát triển. Các kiến trúc này bổ sung những cơ chế cổng để kiểm soát luồng thông tin, cho phép chúng nắm bắt các phụ thuộc tầm xa hiệu quả hơn.

- **LSTM**: Các mạng LSTM dùng ba cổng (input gate, forget gate và output gate) để điều tiết luồng thông tin đi vào và đi ra khỏi trạng thái ô, giúp chúng ghi nhớ hoặc quên thông tin qua các chuỗi dài. Input gate kiểm soát lượng thông tin mới được thêm vào dựa trên đầu vào và trạng thái ẩn trước đó; forget gate kiểm soát lượng thông tin cần loại bỏ. Kết hợp input gate và forget gate, ta có trạng thái mới. Cuối cùng, kết hợp trạng thái ô mới với đầu vào và trạng thái ẩn trước đó, ta cũng có trạng thái ẩn mới.
- **GRU**: Các mạng GRU đơn giản hóa kiến trúc LSTM bằng cách kết hợp input gate và forget gate thành một update gate duy nhất, giúp chúng hiệu quả hơn về mặt tính toán mà vẫn nắm bắt được các phụ thuộc tầm xa.

## LLMs (Large Language Models)

Large Language Models (LLM) là một loại mô hình deep learning được thiết kế riêng cho các tác vụ xử lý ngôn ngữ tự nhiên. Chúng được huấn luyện trên lượng lớn dữ liệu văn bản và có thể tạo văn bản giống con người, trả lời câu hỏi, dịch ngôn ngữ và thực hiện nhiều tác vụ khác liên quan đến ngôn ngữ.
LLM thường dựa trên kiến trúc transformer, sử dụng các cơ chế self-attention để nắm bắt mối quan hệ giữa các từ trong một chuỗi, giúp chúng hiểu ngữ cảnh và tạo văn bản mạch lạc.

### Transformer Architecture <sup>[[4]](#references)</sup>
Kiến trúc transformer là nền tảng của nhiều LLM. Kiến trúc này gồm cấu trúc encoder-decoder, trong đó encoder xử lý chuỗi đầu vào và decoder tạo chuỗi đầu ra. Các thành phần chính của kiến trúc transformer gồm:
- **Self-Attention Mechanism**: Cơ chế này cho phép mô hình cân nhắc mức độ quan trọng của các từ khác nhau trong chuỗi khi tạo biểu diễn. Cơ chế tính điểm attention dựa trên mối quan hệ giữa các từ, giúp mô hình tập trung vào ngữ cảnh liên quan.
- **Multi-Head Attention**: Thành phần này cho phép mô hình nắm bắt nhiều mối quan hệ giữa các từ bằng cách sử dụng nhiều attention head, mỗi head tập trung vào các khía cạnh khác nhau của đầu vào.
- **Positional Encoding**: Vì transformer không có sẵn khái niệm về thứ tự từ, positional encoding được thêm vào các embedding đầu vào để cung cấp thông tin về vị trí của từ trong chuỗi.

## Diffusion Models <sup>[[5]](#references)</sup>
Diffusion models là một lớp mô hình generative học cách tạo dữ liệu bằng cách mô phỏng một quá trình khuếch tán. Chúng đặc biệt hiệu quả với các tác vụ như tạo ảnh và đã trở nên phổ biến trong những năm gần đây.
Diffusion models hoạt động bằng cách dần biến đổi một phân phối nhiễu đơn giản thành một phân phối dữ liệu phức tạp thông qua một chuỗi bước khuếch tán. Các thành phần chính của diffusion models gồm:
- **Forward Diffusion Process**: Quá trình này dần thêm nhiễu vào dữ liệu, biến đổi dữ liệu thành một phân phối nhiễu đơn giản. Forward diffusion process thường được xác định bằng một chuỗi mức nhiễu, trong đó mỗi mức tương ứng với một lượng nhiễu cụ thể được thêm vào dữ liệu.
- **Reverse Diffusion Process**: Quá trình này học cách đảo ngược forward diffusion process, dần khử nhiễu dữ liệu để tạo mẫu từ phân phối mục tiêu. Reverse diffusion process được huấn luyện bằng hàm loss khuyến khích mô hình tái tạo dữ liệu gốc từ các mẫu nhiễu.

Ngoài ra, để tạo ảnh từ prompt văn bản, diffusion models thường thực hiện các bước sau:
1. **Text Encoding**: Prompt văn bản được mã hóa thành biểu diễn latent bằng text encoder (ví dụ: mô hình dựa trên transformer). Biểu diễn này nắm bắt ý nghĩa ngữ nghĩa của văn bản.
2. **Noise Sampling**: Một vector nhiễu ngẫu nhiên được lấy mẫu từ phân phối Gaussian.
3. **Diffusion Steps**: Mô hình áp dụng một chuỗi bước khuếch tán, dần biến đổi vector nhiễu thành ảnh tương ứng với prompt văn bản. Mỗi bước gồm việc áp dụng các phép biến đổi đã học để khử nhiễu ảnh.

## References

- [1] [PyTorch - Hướng dẫn về Neural Networks](https://docs.pytorch.org/tutorials/beginner/blitz/neural_networks_tutorial.html)
- [2] [PyTorch - Conv2d](https://docs.pytorch.org/docs/stable/generated/torch.nn.Conv2d.html)
- [3] [PyTorch - LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html)
- [4] [PyTorch - Transformer](https://docs.pytorch.org/docs/stable/generated/torch.nn.Transformer.html)
- [5] [Mô hình khuếch tán xác suất khử nhiễu](https://arxiv.org/abs/2006.11239)
{{#include ../banners/hacktricks-training.md}}
