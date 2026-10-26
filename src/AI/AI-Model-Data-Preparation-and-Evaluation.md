# Chuẩn bị và đánh giá dữ liệu mô hình

{{#include ../banners/hacktricks-training.md}}

Chuẩn bị dữ liệu mô hình là bước quan trọng trong quy trình machine learning, vì bước này chuyển đổi dữ liệu thô sang định dạng phù hợp để huấn luyện các mô hình machine learning. Quy trình này gồm một số bước chính:

1. **Thu thập dữ liệu**: Thu thập dữ liệu từ nhiều nguồn, chẳng hạn như cơ sở dữ liệu, API hoặc tệp. Dữ liệu có thể có cấu trúc (ví dụ: bảng) hoặc phi cấu trúc (ví dụ: văn bản, hình ảnh).
2. **Làm sạch dữ liệu**: Loại bỏ hoặc sửa các điểm dữ liệu sai, không đầy đủ hoặc không liên quan. Bước này có thể bao gồm xử lý giá trị bị thiếu, loại bỏ dữ liệu trùng lặp và lọc các giá trị ngoại lệ.
3. **Chuyển đổi dữ liệu**: Chuyển đổi dữ liệu sang định dạng phù hợp để lập mô hình. Việc này có thể bao gồm chuẩn hóa, co giãn, mã hóa biến phân loại và tạo đặc trưng mới bằng các kỹ thuật như feature engineering.
4. **Chia dữ liệu**: Chia tập dữ liệu thành các tập huấn luyện, xác thực và kiểm tra để đảm bảo mô hình có thể tổng quát hóa tốt với dữ liệu chưa từng gặp.

## Thu thập dữ liệu

Thu thập dữ liệu bao gồm việc lấy dữ liệu từ nhiều nguồn, có thể gồm:
- **Cơ sở dữ liệu**: Trích xuất dữ liệu từ cơ sở dữ liệu quan hệ (ví dụ: cơ sở dữ liệu SQL) hoặc cơ sở dữ liệu NoSQL (ví dụ: MongoDB).
- **API**: Lấy dữ liệu từ web API, có thể cung cấp dữ liệu theo thời gian thực hoặc dữ liệu lịch sử.
- **Tệp**: Đọc dữ liệu từ các tệp có định dạng như CSV, JSON hoặc XML.
- **Web Scraping**: Thu thập dữ liệu từ các trang web bằng kỹ thuật web scraping.

Tùy theo mục tiêu của dự án machine learning, dữ liệu sẽ được trích xuất và thu thập từ các nguồn phù hợp để đảm bảo dữ liệu phản ánh đúng lĩnh vực của bài toán.

## Làm sạch dữ liệu <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Làm sạch dữ liệu là quá trình xác định và sửa lỗi hoặc điểm không nhất quán trong tập dữ liệu. Bước này rất cần thiết để đảm bảo chất lượng dữ liệu dùng trong quá trình huấn luyện mô hình machine learning. Các tác vụ chính trong quá trình làm sạch dữ liệu gồm:
- **Xử lý giá trị bị thiếu**: Xác định và xử lý các điểm dữ liệu bị thiếu. Các chiến lược phổ biến gồm:
  - Xóa các hàng hoặc cột có giá trị bị thiếu.
  - Điền giá trị bị thiếu bằng các kỹ thuật như điền giá trị trung bình, trung vị hoặc mode.
  - Sử dụng các phương pháp nâng cao như điền giá trị bằng K-nearest neighbors (KNN) hoặc hồi quy.
- **Loại bỏ dữ liệu trùng lặp**: Xác định và xóa các bản ghi trùng lặp để đảm bảo mỗi điểm dữ liệu là duy nhất.
- **Lọc giá trị ngoại lệ**: Phát hiện và loại bỏ các giá trị ngoại lệ có thể làm sai lệch hiệu suất của mô hình. Có thể dùng các kỹ thuật như Z-score, IQR (Interquartile Range) hoặc hình ảnh trực quan (ví dụ: biểu đồ hộp) để xác định giá trị ngoại lệ.

### Ví dụ về làm sạch dữ liệu

```python
import re

import numpy as np
import pandas as pd
from sklearn.impute import KNNImputer, SimpleImputer

# Load the dataset
df = pd.read_csv('data.csv')

# Finding invalid values based on a specific function
def is_valid_positive_int(num):
    try:
        num = int(num)
        return 1 <= num <= 31
    except ValueError:
        return False

invalid_days = df[~df['days'].astype(str).apply(is_valid_positive_int)]

## Dropping rows with invalid days
df = df.drop(invalid_days.index, errors='ignore')



# Set "NaN" values to a specific value
## For example, setting NaN values in the 'days' column to 0
df['days'] = pd.to_numeric(df['days'], errors='coerce')

## For example, set "NaN" to not ips
def is_valid_ip(ip):
    pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$')
    if pd.isna(ip) or not pattern.match(str(ip)):
        return np.nan
    return ip
df['ip'] = df['ip'].apply(is_valid_ip)

# Filling missing values based on different strategies
numeric_cols = ["days", "hours", "minutes"]
categorical_cols = ["ip", "status"]

## Filling missing values in numeric columns with the median
num_imputer = SimpleImputer(strategy='median')
df[numeric_cols] = num_imputer.fit_transform(df[numeric_cols])

## Filling missing values in categorical columns with the most frequent value
cat_imputer = SimpleImputer(strategy='most_frequent')
df[categorical_cols] = cat_imputer.fit_transform(df[categorical_cols])

## Filling missing values in numeric columns using KNN imputation
knn_imputer = KNNImputer(n_neighbors=5)
df[numeric_cols] = knn_imputer.fit_transform(df[numeric_cols])



# Filling missing values
df.fillna(df.mean(numeric_only=True), inplace=True)

# Removing duplicates
df.drop_duplicates(inplace=True)
# Filtering outliers using Z-score
from scipy import stats
z_scores = np.abs(stats.zscore(df.select_dtypes(include=['float64', 'int64']), nan_policy='omit'))
df = df[(z_scores < 3).all(axis=1)]
```

## Chuyển đổi dữ liệu <sup>[[1]](#references)</sup>

Chuyển đổi dữ liệu là quá trình chuyển dữ liệu sang định dạng phù hợp để mô hình hóa. Bước này có thể bao gồm:
- **Chuẩn hóa và tiêu chuẩn hóa**: Điều chỉnh tỷ lệ các đặc trưng số về một khoảng chung, thường là [0, 1] hoặc [-1, 1]. Việc này có thể giúp các thuật toán tối ưu hội tụ tốt hơn.
    - **Min-Max Scaling**: Đưa các đặc trưng về một khoảng cố định, thường là [0, 1]. Thực hiện bằng công thức: `X' = (X - X_{min}) / (X_{max} - X_{min})`
    - **Z-Score Normalization**: Chuẩn hóa các đặc trưng bằng cách trừ đi giá trị trung bình rồi chia cho độ lệch chuẩn, tạo ra phân phối có giá trị trung bình bằng 0 và độ lệch chuẩn bằng 1. Thực hiện bằng công thức: `X' = (X - μ) / σ`, trong đó μ là giá trị trung bình và σ là độ lệch chuẩn.
    - **Độ lệch và độ nhọn**: Điều chỉnh phân phối đặc trưng bằng các phép biến đổi như logarit, căn bậc hai hoặc Box-Cox. Ví dụ, phép biến đổi logarit có thể làm giảm độ lệch dương.
    - **Chuẩn hóa chuỗi**: Chuyển đổi chuỗi sang định dạng nhất quán, chẳng hạn như:
      - Chuyển thành chữ thường
      - Loại bỏ ký tự đặc biệt (giữ lại các ký tự cần thiết)
      - Loại bỏ stop word (các từ phổ biến không đóng góp vào ý nghĩa, chẳng hạn như "the", "is", "and")
      - Loại bỏ các từ xuất hiện quá thường xuyên hoặc quá hiếm (ví dụ: từ xuất hiện trong hơn 90% tài liệu hoặc ít hơn 5 lần trong kho ngữ liệu)
      - Xóa khoảng trắng thừa
      - Stemming/Lemmatization: Đưa từ về dạng gốc hoặc căn tố (ví dụ: "running" thành "run").

- **Mã hóa biến phân loại**: Chuyển đổi biến phân loại thành biểu diễn số. Các kỹ thuật phổ biến gồm:
  - **One-Hot Encoding**: Tạo các cột nhị phân cho từng danh mục.
    - Ví dụ: nếu một đặc trưng có các danh mục "red", "green" và "blue", nó sẽ được chuyển thành ba cột nhị phân: `is_red`(100), `is_green`(010) và `is_blue`(001).
  - **Label Encoding**: Gán một số nguyên duy nhất cho từng danh mục.
    - Ví dụ: "red" = 0, "green" = 1, "blue" = 2.
  - **Ordinal Encoding**: Gán số nguyên dựa trên thứ tự của các danh mục.
    - Ví dụ: nếu các danh mục là "low", "medium" và "high", chúng có thể được mã hóa lần lượt thành 0, 1 và 2.
  - **Hashing Encoding**: Dùng hàm băm để chuyển danh mục thành các vector có kích thước cố định; kỹ thuật này có thể hữu ích với các biến phân loại có nhiều giá trị riêng biệt.
    - Ví dụ: nếu một đặc trưng có nhiều danh mục duy nhất, hashing có thể giảm số chiều mà vẫn giữ lại một phần thông tin về các danh mục.
  - **Bag of Words (BoW)**: Biểu diễn dữ liệu văn bản dưới dạng ma trận số lượng hoặc tần suất từ, trong đó mỗi hàng tương ứng với một tài liệu và mỗi cột tương ứng với một từ duy nhất trong kho ngữ liệu.
    - Ví dụ: nếu kho ngữ liệu có các từ "cat", "dog" và "fish", một tài liệu chứa "cat" và "dog" sẽ được biểu diễn thành [1, 1, 0]. Biểu diễn cụ thể này được gọi là "unigram" và không ghi nhận thứ tự từ, nên làm mất thông tin ngữ nghĩa.
    - **Bigram/Trigram**: Mở rộng BoW để ghi nhận các chuỗi từ (bigram hoặc trigram), qua đó giữ lại một phần ngữ cảnh. Ví dụ: "cat and dog" sẽ được biểu diễn bằng bigram [1, 1] cho "cat and" và [1, 1] cho "and dog". Trong trường hợp này, biểu diễn thu thập thêm thông tin ngữ nghĩa (làm tăng số chiều), nhưng chỉ cho 2 hoặc 3 từ mỗi lần.
  - **TF-IDF (Tần suất thuật ngữ-Tần suất tài liệu nghịch đảo)**: Thước đo thống kê đánh giá mức độ quan trọng của một từ trong tài liệu so với tập hợp tài liệu (kho ngữ liệu). Thước đo này kết hợp tần suất thuật ngữ (mức độ thường xuyên một từ xuất hiện trong tài liệu) và tần suất tài liệu nghịch đảo (mức độ hiếm của từ trong toàn bộ tài liệu).
    - Ví dụ: nếu từ "cat" xuất hiện thường xuyên trong một tài liệu nhưng hiếm trong toàn bộ kho ngữ liệu, từ này sẽ có điểm TF-IDF cao, cho thấy nó quan trọng trong tài liệu đó.

- **Thiết kế đặc trưng**: Tạo đặc trưng mới từ các đặc trưng hiện có để tăng khả năng dự đoán của mô hình. Việc này có thể bao gồm kết hợp đặc trưng, trích xuất thành phần ngày/giờ hoặc áp dụng các phép biến đổi theo lĩnh vực cụ thể.

## Chia tách dữ liệu <sup>[[3]](#references)</sup>

Chia tách dữ liệu là quá trình chia tập dữ liệu thành các tập con riêng biệt để huấn luyện, xác thực và kiểm thử. Việc này cần thiết để đánh giá hiệu suất của mô hình trên dữ liệu chưa từng thấy và ngăn hiện tượng overfitting. Các chiến lược phổ biến gồm:
- **Train-Test Split**: Chia tập dữ liệu thành tập huấn luyện (thường chiếm 60-80% dữ liệu), tập xác thực (10-15% dữ liệu) để tinh chỉnh siêu tham số và tập kiểm thử (10-15% dữ liệu). Mô hình được huấn luyện trên tập huấn luyện và đánh giá trên tập kiểm thử.
  - Ví dụ: với tập dữ liệu gồm 1000 mẫu, bạn có thể dùng 700 mẫu để huấn luyện, 150 mẫu để xác thực và 150 mẫu để kiểm thử.
- **Lấy mẫu phân tầng**: Đảm bảo phân phối lớp trong các tập huấn luyện và kiểm thử tương tự như trong toàn bộ tập dữ liệu. Điều này đặc biệt quan trọng với các tập dữ liệu mất cân bằng, trong đó một số lớp có thể có số mẫu ít hơn đáng kể so với các lớp khác.
- **Time Series Split**: Với dữ liệu chuỗi thời gian, tập dữ liệu được chia theo thời gian, đảm bảo tập huấn luyện chứa dữ liệu từ các giai đoạn trước và tập kiểm thử chứa dữ liệu từ các giai đoạn sau. Điều này giúp đánh giá hiệu suất của mô hình trên dữ liệu tương lai.
- **K-Fold Cross-Validation**: Chia tập dữ liệu thành K tập con (fold) và huấn luyện mô hình K lần; mỗi lần dùng một fold khác nhau làm tập kiểm thử, còn các fold còn lại làm tập huấn luyện. Cách này giúp đảm bảo mô hình được đánh giá trên nhiều tập con dữ liệu, từ đó đưa ra ước tính hiệu suất đáng tin cậy hơn.

## Đánh giá mô hình <sup>[[4]](#references)</sup>

Đánh giá mô hình là quá trình xác định hiệu suất của mô hình machine learning trên dữ liệu chưa từng thấy. Quá trình này sử dụng nhiều chỉ số để định lượng mức độ khái quát hóa của mô hình trên dữ liệu mới. Các chỉ số đánh giá phổ biến gồm:

### Accuracy

Accuracy là tỷ lệ số mẫu được dự đoán chính xác trên tổng số mẫu. Chỉ số này được tính như sau:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```

> [!TIP]
> Accuracy là một chỉ số đơn giản và trực quan, nhưng có thể không phù hợp với các tập dữ liệu mất cân bằng, trong đó một lớp chiếm ưu thế hơn các lớp khác, vì nó có thể gây hiểu lầm về hiệu suất của mô hình. Ví dụ: nếu 90% dữ liệu thuộc lớp A và mô hình dự đoán tất cả các mẫu là lớp A, mô hình sẽ đạt accuracy 90%, nhưng sẽ không hữu ích trong việc dự đoán lớp B.

### Precision

Precision là tỷ lệ dự đoán dương tính đúng trên tổng số dự đoán dương tính của mô hình. Chỉ số này được tính như sau:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```

> [!TIP]
> Độ chính xác đặc biệt quan trọng trong những tình huống mà false positive gây tốn kém hoặc không mong muốn, chẳng hạn như chẩn đoán y tế hoặc phát hiện gian lận. Ví dụ: nếu một mô hình dự đoán 100 trường hợp là dương tính, nhưng chỉ có 80 trường hợp thực sự dương tính, thì độ chính xác sẽ là 0.8 (80%).

### Độ bao phủ (Độ nhạy)

Độ bao phủ, còn gọi là độ nhạy hoặc tỷ lệ dương tính thật, là tỷ lệ các dự đoán dương tính thật trên tổng số trường hợp thực tế dương tính. Độ bao phủ được tính như sau:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```

> [!TIP]
> Recall rất quan trọng trong các tình huống mà false negative gây tốn kém hoặc không mong muốn, chẳng hạn như phát hiện bệnh hoặc lọc spam. Ví dụ, nếu một model xác định đúng 80 trong số 100 trường hợp dương tính thực tế, recall sẽ là 0.8 (80%).

### Điểm F1

Điểm F1 là trung bình điều hòa của precision và recall, giúp cân bằng hai chỉ số này. Công thức tính như sau:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```

> [!TIP]
> Điểm F1 đặc biệt hữu ích khi làm việc với các tập dữ liệu mất cân bằng, vì nó xét đến cả false positive và false negative. Điểm này cung cấp một chỉ số duy nhất thể hiện sự cân bằng giữa precision và recall. Ví dụ, nếu một mô hình có precision là 0.8 và recall là 0.6, điểm F1 sẽ xấp xỉ 0.69.

### ROC-AUC (Đặc tính hoạt động của bộ thu - Diện tích dưới đường cong)

Chỉ số ROC-AUC đánh giá khả năng phân biệt giữa các lớp của mô hình bằng cách biểu diễn tỷ lệ true positive (độ nhạy) theo tỷ lệ false positive tại nhiều ngưỡng khác nhau. Diện tích dưới đường cong ROC (AUC) định lượng hiệu suất của mô hình; giá trị 1 biểu thị phân loại hoàn hảo, còn giá trị 0.5 biểu thị việc đoán ngẫu nhiên.

> [!TIP]
> ROC-AUC đặc biệt hữu ích cho các bài toán phân loại nhị phân và cung cấp cái nhìn toàn diện về hiệu suất của mô hình ở các ngưỡng khác nhau. Chỉ số này ít nhạy với tình trạng mất cân bằng lớp hơn accuracy. Ví dụ, mô hình có AUC là 0.9 cho thấy khả năng phân biệt các trường hợp dương tính và âm tính cao.

### Specificity

Specificity, còn gọi là tỷ lệ true negative, là tỷ lệ dự đoán âm tính đúng trên tổng số trường hợp âm tính thực tế. Chỉ số này được tính như sau:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```

> [!TIP]
> Độ đặc hiệu rất quan trọng trong những tình huống mà kết quả dương tính giả gây tốn kém hoặc không mong muốn, chẳng hạn như xét nghiệm y tế hoặc phát hiện gian lận. Chỉ số này giúp đánh giá mức độ hiệu quả của mô hình trong việc nhận diện các trường hợp âm tính. Ví dụ, nếu mô hình xác định chính xác 90 trong số 100 trường hợp âm tính thực tế, độ đặc hiệu sẽ là 0.9 (90%).

### Hệ số tương quan Matthews (MCC)
Hệ số tương quan Matthews (MCC) là thước đo chất lượng của các phép phân loại nhị phân. Chỉ số này tính đến cả kết quả dương tính và âm tính thật lẫn giả, qua đó đưa ra đánh giá cân bằng về hiệu suất của mô hình. MCC được tính như sau:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
where:
- **TP**: Dương tính thật
- **TN**: Âm tính thật
- **FP**: Dương tính giả
- **FN**: Âm tính giả

> [!TIP]
> MCC có giá trị từ -1 đến 1, trong đó 1 biểu thị phân loại hoàn hảo, 0 biểu thị dự đoán ngẫu nhiên và -1 biểu thị sự bất đồng hoàn toàn giữa dự đoán và quan sát. Chỉ số này đặc biệt hữu ích với các tập dữ liệu mất cân bằng vì tính đến cả bốn thành phần của ma trận nhầm lẫn.

### Sai số tuyệt đối trung bình (MAE)
Sai số tuyệt đối trung bình (MAE) là một metric hồi quy đo lường độ chênh lệch tuyệt đối trung bình giữa các giá trị dự đoán và giá trị thực tế. Công thức tính như sau:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
trong đó:
- **n**: Số lượng mẫu
- **y_i**: Giá trị thực tế của mẫu i
- **ŷ_i**: Giá trị dự đoán của mẫu i

> [!TIP]
> MAE giúp diễn giải trực quan sai số trung bình của các dự đoán, nhờ đó dễ hiểu. Chỉ số này ít nhạy cảm với các giá trị ngoại lệ hơn những chỉ số khác như Mean Squared Error (MSE). Ví dụ, nếu một model có MAE bằng 5, điều đó có nghĩa là trung bình các dự đoán của model lệch 5 đơn vị so với giá trị thực tế.

### Ma trận nhầm lẫn

Ma trận nhầm lẫn là một bảng tóm tắt hiệu suất của model phân loại bằng cách hiển thị số lượng dự đoán true positive, true negative, false positive và false negative. Bảng này cung cấp cái nhìn chi tiết về hiệu suất của model trên từng lớp.

|               | Positive được dự đoán | Negative được dự đoán |
|---------------|---------------------|---------------------|
| Positive thực tế| True Positive (TP)  | False Negative (FN)  |
| Negative thực tế| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: Model dự đoán chính xác lớp positive.
- **True Negative (TN)**: Model dự đoán chính xác lớp negative.
- **False Positive (FP)**: Model dự đoán nhầm lớp positive (lỗi Type I).
- **False Negative (FN)**: Model dự đoán nhầm lớp negative (lỗi Type II).

Có thể dùng ma trận nhầm lẫn để tính các chỉ số đánh giá như accuracy, precision, recall và F1 score.

## References

- [1] [scikit-learn - Tiền xử lý dữ liệu](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Bù các giá trị bị thiếu](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Cross-validation: đánh giá hiệu suất của estimator](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Các chỉ số và cách tính điểm](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
