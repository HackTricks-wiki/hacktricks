# Các thuật toán học có giám sát

{{#include ../banners/hacktricks-training.md}}

## Thông tin cơ bản

Học có giám sát sử dụng dữ liệu được gắn nhãn để huấn luyện các mô hình có thể đưa ra dự đoán trên những dữ liệu đầu vào mới chưa từng thấy. Trong an ninh mạng, machine learning có giám sát được ứng dụng rộng rãi vào các tác vụ như phát hiện xâm nhập (phân loại lưu lượng mạng là *bình thường* hoặc *tấn công*), phát hiện malware (phân biệt phần mềm độc hại với phần mềm lành tính), phát hiện phishing (xác định các trang web hoặc email lừa đảo) và lọc spam, cùng nhiều tác vụ khác.<sup>[[1]](#references)</sup> Mỗi thuật toán đều có thế mạnh riêng và phù hợp với các loại bài toán khác nhau (phân loại hoặc hồi quy). Dưới đây, chúng ta sẽ xem xét các thuật toán học có giám sát chính, giải thích cách chúng hoạt động và minh họa cách sử dụng chúng trên các tập dữ liệu an ninh mạng thực tế. Chúng ta cũng sẽ thảo luận về cách kết hợp các mô hình (học ensemble) thường có thể cải thiện hiệu suất dự đoán.

## Thuật toán

-   **Linear Regression:** Thuật toán hồi quy nền tảng dùng để dự đoán các kết quả dạng số bằng cách khớp một phương trình tuyến tính với dữ liệu.

-   **Logistic Regression:** Thuật toán phân loại (mặc dù tên gọi có chữ hồi quy) sử dụng hàm logistic để mô hình hóa xác suất của một kết quả nhị phân.

-   **Decision Trees:** Các mô hình có cấu trúc dạng cây, phân chia dữ liệu theo các đặc trưng để đưa ra dự đoán; thường được sử dụng vì dễ diễn giải.

-   **Random Forests:** Tổ hợp các decision tree (thông qua bagging) giúp cải thiện độ chính xác và giảm overfitting.

-   **Support Vector Machines (SVM):** Các bộ phân loại tối đa hóa biên, tìm siêu phẳng phân tách tối ưu; có thể sử dụng kernel cho dữ liệu phi tuyến.

-   **Naive Bayes:** Bộ phân loại xác suất dựa trên định lý Bayes, với giả định các đặc trưng độc lập; nổi tiếng với ứng dụng lọc spam.

-   **k-Nearest Neighbors (k-NN):** Bộ phân loại "dựa trên mẫu" đơn giản, gán nhãn cho một mẫu dựa trên lớp chiếm đa số trong các láng giềng gần nhất của nó.

-   **Gradient Boosting Machines:** Các mô hình ensemble (ví dụ: XGBoost, LightGBM) xây dựng một bộ dự đoán mạnh bằng cách lần lượt thêm các learner yếu hơn (thường là decision tree).

Mỗi phần bên dưới cung cấp mô tả cải tiến về thuật toán và **ví dụ mã Python** sử dụng các thư viện như `pandas` và `scikit-learn` (và `PyTorch` cho ví dụ về neural network). Các ví dụ sử dụng những tập dữ liệu an ninh mạng công khai (chẳng hạn như NSL-KDD để phát hiện xâm nhập và tập dữ liệu Phishing Websites) và tuân theo cấu trúc thống nhất:

1.  **Tải tập dữ liệu** (tải xuống qua URL nếu có).

2.  **Tiền xử lý dữ liệu** (ví dụ: mã hóa các đặc trưng phân loại, chuẩn hóa giá trị, chia thành các tập huấn luyện/kiểm tra).

3.  **Huấn luyện mô hình** trên dữ liệu huấn luyện.

4.  **Đánh giá** trên tập kiểm tra bằng các chỉ số: accuracy, precision, recall, F1-score và ROC AUC cho bài toán phân loại (và mean squared error cho bài toán hồi quy).

Hãy cùng tìm hiểu từng thuật toán:

### Linear Regression

Linear regression là thuật toán **hồi quy** dùng để dự đoán các giá trị số liên tục. Thuật toán giả định rằng có mối quan hệ tuyến tính giữa các đặc trưng đầu vào (biến độc lập) và đầu ra (biến phụ thuộc). Mô hình cố gắng khớp một đường thẳng (hoặc siêu phẳng trong không gian nhiều chiều) mô tả tốt nhất mối quan hệ giữa các đặc trưng và biến mục tiêu. Việc này thường được thực hiện bằng cách tối thiểu hóa tổng bình phương sai số giữa các giá trị dự đoán và giá trị thực tế (phương pháp Ordinary Least Squares).<sup>[[2]](#references)</sup>

Cách đơn giản nhất để biểu diễn linear regression là bằng một đường thẳng:

```plaintext
y = mx + b
```

Where:

- `y` là giá trị dự đoán (đầu ra)
- `m` là độ dốc của đường thẳng (hệ số)
- `x` là đặc trưng đầu vào
- `b` là tung độ gốc

Mục tiêu của linear regression là tìm đường thẳng phù hợp nhất, sao cho chênh lệch giữa giá trị dự đoán và giá trị thực tế trong tập dữ liệu là nhỏ nhất. Tất nhiên, đây là trường hợp rất đơn giản: một đường thẳng phân tách 2 nhóm. Nhưng khi thêm nhiều chiều hơn, đường thẳng sẽ trở nên phức tạp hơn:

```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```

> [!TIP]
> *Các trường hợp sử dụng trong an ninh mạng:* Bản thân hồi quy tuyến tính ít được dùng cho các tác vụ bảo mật cốt lõi (thường là phân loại), nhưng có thể được áp dụng để dự đoán các kết quả dạng số. Ví dụ, có thể dùng hồi quy tuyến tính để **dự đoán lưu lượng mạng** hoặc **ước tính số cuộc tấn công trong một khoảng thời gian** dựa trên dữ liệu lịch sử. Phương pháp này cũng có thể dự đoán điểm rủi ro hoặc thời gian dự kiến cho đến khi phát hiện một cuộc tấn công dựa trên một số chỉ số hệ thống. Trên thực tế, các thuật toán phân loại (như hồi quy logistic hoặc cây) được dùng phổ biến hơn để phát hiện xâm nhập hoặc malware, nhưng hồi quy tuyến tính đóng vai trò nền tảng và hữu ích cho các phân tích hướng hồi quy.

#### **Đặc điểm chính của hồi quy tuyến tính:**

-   **Loại bài toán:** Hồi quy (dự đoán các giá trị liên tục). Không phù hợp để phân loại trực tiếp, trừ khi áp dụng một ngưỡng cho đầu ra.

-   **Khả năng diễn giải:** Cao -- các hệ số dễ diễn giải, thể hiện tác động tuyến tính của từng đặc trưng.

-   **Ưu điểm:** Đơn giản và nhanh; là mô hình cơ sở tốt cho các tác vụ hồi quy; hoạt động hiệu quả khi mối quan hệ thực tế gần tuyến tính.

-   **Hạn chế:** Không thể nắm bắt các mối quan hệ phức tạp hoặc phi tuyến (nếu không thiết kế đặc trưng thủ công); dễ bị underfitting nếu các mối quan hệ là phi tuyến; nhạy cảm với outlier, có thể làm sai lệch kết quả.

-   **Tìm đường khớp tốt nhất:** Để tìm đường thẳng khớp tốt nhất nhằm phân tách các danh mục có thể có, ta sử dụng một phương pháp gọi là **Ordinary Least Squares (OLS)**. Phương pháp này giảm thiểu tổng bình phương các chênh lệch giữa giá trị quan sát được và giá trị do mô hình tuyến tính dự đoán.

<details>
<summary>Ví dụ -- Dự đoán thời lượng kết nối (hồi quy) trong tập dữ liệu xâm nhập
</summary>
Dưới đây, chúng ta minh họa hồi quy tuyến tính bằng tập dữ liệu an ninh mạng NSL-KDD. Ta sẽ xem đây là bài toán hồi quy bằng cách dự đoán `duration` của các kết nối mạng dựa trên những đặc trưng khác. (Trên thực tế, `duration` là một đặc trưng của NSL-KDD; ở đây ta chỉ dùng nó để minh họa hồi quy.) Ta tải tập dữ liệu, tiền xử lý (mã hóa các đặc trưng phân loại), huấn luyện mô hình hồi quy tuyến tính và đánh giá Mean Squared Error (MSE) cùng điểm R² trên tập kiểm thử.


```python
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error, r2_score

# ── 1. Column names taken from the NSL‑KDD documentation ──────────────
col_names = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","class","difficulty_level"
]

# ── 2. Load data *without* header row ─────────────────────────────────
train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# ── 3. Encode the 3 nominal features ─────────────────────────────────
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
    df_train[col] = le.transform(df_train[col])
    df_test[col]  = le.transform(df_test[col])

# ── 4. Prepare features / target ─────────────────────────────────────
X_train = df_train.drop(columns=['class', 'difficulty_level', 'duration'])
y_train = df_train['duration']

X_test  = df_test.drop(columns=['class', 'difficulty_level', 'duration'])
y_test  = df_test['duration']

# ── 5. Train & evaluate simple Linear Regression ─────────────────────
model = LinearRegression().fit(X_train, y_train)
y_pred = model.predict(X_test)

print(f"Test MSE: {mean_squared_error(y_test, y_pred):.2f}")
print(f"Test R² : {r2_score(y_test, y_pred):.3f}")

"""
Test MSE: 3021333.56
Test R² : -0.526
"""
```

Trong ví dụ này, mô hình hồi quy tuyến tính cố gắng dự đoán `duration` của kết nối từ các đặc trưng mạng khác. Chúng ta đo hiệu suất bằng Mean Squared Error (MSE) và R². R² gần 1.0 cho biết mô hình giải thích được phần lớn phương sai của `duration`, trong khi R² thấp hoặc âm cho biết mô hình khớp kém. (Đừng ngạc nhiên nếu R² ở đây thấp — có thể khó dự đoán `duration` từ các đặc trưng đã cho, và hồi quy tuyến tính có thể không nắm bắt được các mẫu nếu chúng phức tạp.)
</details>

### Hồi quy Logistic

Hồi quy logistic là thuật toán **phân loại**, mô hình hóa xác suất một mẫu thuộc về một lớp cụ thể (thường là lớp "dương tính"). Dù tên gọi như vậy, hồi quy *logistic* được dùng cho các kết quả rời rạc (không giống hồi quy tuyến tính, vốn dùng cho các kết quả liên tục). Thuật toán này đặc biệt được dùng cho **phân loại nhị phân** (hai lớp, ví dụ: độc hại và lành tính), nhưng có thể mở rộng cho các bài toán đa lớp (bằng cách sử dụng softmax hoặc phương pháp one-vs-rest).<sup>[[3]](#references)</sup>

Hồi quy logistic sử dụng hàm logistic (còn gọi là hàm sigmoid) để ánh xạ các giá trị dự đoán thành xác suất. Lưu ý rằng hàm sigmoid trả về các giá trị từ 0 đến 1, tăng theo đường cong hình chữ S tùy theo yêu cầu của bài toán phân loại; đặc điểm này hữu ích cho các tác vụ phân loại nhị phân. Do đó, mỗi đặc trưng của mỗi đầu vào được nhân với trọng số tương ứng, sau đó kết quả được đưa qua hàm sigmoid để tạo ra xác suất:

```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```

Where:

- `p(y=1|x)` là xác suất đầu ra `y` bằng 1 khi biết đầu vào `x`
- `e` là cơ số của logarit tự nhiên
- `z` là tổ hợp tuyến tính của các đặc trưng đầu vào, thường được biểu diễn dưới dạng `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Lưu ý rằng ở dạng đơn giản nhất, nó là một đường thẳng, nhưng trong các trường hợp phức tạp hơn, nó trở thành một siêu phẳng với nhiều chiều (mỗi chiều ứng với một đặc trưng).

> [!TIP]
> *Các trường hợp sử dụng trong an ninh mạng:* Vì nhiều vấn đề bảo mật về bản chất là các quyết định có/không, hồi quy logistic được sử dụng rộng rãi. Ví dụ, hệ thống phát hiện xâm nhập có thể dùng hồi quy logistic để quyết định một kết nối mạng có phải là cuộc tấn công hay không dựa trên các đặc trưng của kết nối đó. Trong phát hiện phishing, hồi quy logistic có thể kết hợp các đặc trưng của một website (độ dài URL, sự hiện diện của ký hiệu "@", v.v.) để tính xác suất website đó là phishing. Phương pháp này từng được sử dụng trong các bộ lọc spam thế hệ đầu và vẫn là một mô hình cơ sở vững chắc cho nhiều tác vụ phân loại.

#### Hồi quy Logistic cho phân loại không nhị phân

Hồi quy logistic được thiết kế cho phân loại nhị phân, nhưng có thể được mở rộng để xử lý các bài toán đa lớp bằng những kỹ thuật như **one-vs-rest** (OvR) hoặc **softmax regression**. Trong OvR, một mô hình hồi quy logistic riêng được huấn luyện cho từng lớp, xem lớp đó là lớp dương và tất cả các lớp còn lại là lớp âm. Lớp có xác suất dự đoán cao nhất được chọn làm dự đoán cuối cùng. Softmax regression khái quát hóa hồi quy logistic cho nhiều lớp bằng cách áp dụng hàm softmax vào lớp đầu ra, tạo ra phân phối xác suất trên tất cả các lớp.

#### **Đặc điểm chính của hồi quy Logistic:**

-   **Loại bài toán:** Phân loại (thường là nhị phân). Mô hình dự đoán xác suất của lớp dương.

-   **Khả năng diễn giải:** Cao -- giống như hồi quy tuyến tính, các hệ số đặc trưng có thể cho biết mỗi đặc trưng ảnh hưởng như thế nào đến log-odds của kết quả. Tính minh bạch này thường hữu ích trong bảo mật để hiểu những yếu tố nào góp phần tạo ra cảnh báo.

-   **Ưu điểm:** Đơn giản và huấn luyện nhanh; hoạt động tốt khi mối quan hệ giữa các đặc trưng và log-odds của kết quả là tuyến tính. Mô hình đưa ra xác suất, cho phép chấm điểm rủi ro. Với regularization phù hợp, mô hình khái quát hóa tốt và xử lý đa cộng tuyến tốt hơn hồi quy tuyến tính thông thường.

-   **Hạn chế:** Giả định ranh giới quyết định trong không gian đặc trưng là tuyến tính (không hiệu quả nếu ranh giới thực tế phức tạp/phi tuyến). Mô hình có thể hoạt động kém trong các bài toán mà tương tác hoặc tác động phi tuyến đóng vai trò quan trọng, trừ khi bạn tự thêm các đặc trưng đa thức hoặc tương tác. Ngoài ra, hồi quy logistic kém hiệu quả hơn nếu các lớp không dễ phân tách bằng tổ hợp tuyến tính của các đặc trưng.


<details>
<summary>Ví dụ -- Phát hiện website phishing bằng hồi quy Logistic:</summary>

Chúng ta sẽ sử dụng **Phishing Websites Dataset** (từ kho lưu trữ UCI), gồm các đặc trưng được trích xuất từ website (chẳng hạn URL có chứa địa chỉ IP hay không, tuổi của tên miền, sự hiện diện của các thành phần đáng ngờ trong HTML, v.v.) cùng nhãn cho biết trang web là phishing hay hợp pháp.<sup>[[4]](#references)</sup> Chúng ta huấn luyện một mô hình hồi quy logistic để phân loại website, sau đó đánh giá accuracy, precision, recall, F1-score và ROC AUC trên tập kiểm thử.

```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load dataset
data = fetch_openml(data_id=4534, as_frame=True)  # PhishingWebsites
df   = data.frame
print(df.head()) 

# 2. Target mapping ─ legitimate (1) → 0, everything else → 1
df['Result'] = df['Result'].astype(int)
y = (df['Result'] != 1).astype(int)

# 3. Features
X = df.drop(columns=['Result'])

# 4. Train/test split with stratify
## Stratify ensures balanced classes in train/test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y)

# 5. Scale
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# 6. Logistic Regression
## L‑BFGS is a modern, memory‑efficient “quasi‑Newton” algorithm that works well for medium/large datasets and supports multiclass natively.
## Upper bound on how many optimization steps the solver may take before it gives up.	Not all steps are guaranteed to be taken, but would be the maximum before a "failed to converge" error.
clf = LogisticRegression(max_iter=1000, solver='lbfgs', random_state=42)
clf.fit(X_train, y_train)

# 7. Evaluation
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1-score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.928
Precision: 0.934
Recall   : 0.901
F1-score : 0.917
ROC AUC  : 0.979
"""
```

Trong ví dụ phát hiện phishing này, logistic regression tạo ra xác suất mỗi website là phishing. Đánh giá accuracy, precision, recall và F1 giúp chúng ta nắm được hiệu suất của mô hình. Chẳng hạn, recall cao nghĩa là mô hình phát hiện được phần lớn các trang phishing (điều quan trọng để giảm thiểu các cuộc tấn công bị bỏ sót), còn precision cao nghĩa là mô hình có ít cảnh báo sai (điều quan trọng để tránh khiến chuyên viên phân tích bị quá tải). ROC AUC (Area Under the ROC Curve) cung cấp thước đo hiệu suất không phụ thuộc vào ngưỡng (1.0 là lý tưởng, 0.5 không tốt hơn đoán ngẫu nhiên). Logistic regression thường hoạt động tốt với các tác vụ như vậy, nhưng nếu ranh giới quyết định giữa các trang phishing và trang hợp lệ phức tạp, có thể cần đến các mô hình phi tuyến mạnh hơn.

</details>

### Cây quyết định

Cây quyết định là một **thuật toán học có giám sát** linh hoạt, có thể dùng cho cả tác vụ phân loại lẫn hồi quy. Thuật toán này học một mô hình phân cấp dạng cây về các quyết định dựa trên các đặc trưng của dữ liệu. Mỗi nút bên trong cây biểu thị một phép kiểm tra trên một đặc trưng cụ thể, mỗi nhánh biểu thị một kết quả của phép kiểm tra đó, còn mỗi nút lá biểu thị lớp dự đoán (đối với phân loại) hoặc giá trị dự đoán (đối với hồi quy).<sup>[[5]](#references)</sup>

Để xây dựng cây, các thuật toán như CART (Classification and Regression Tree) sử dụng những thước đo như **độ hỗn tạp Gini** hoặc **information gain (entropy)** để chọn đặc trưng và ngưỡng phân chia dữ liệu phù hợp nhất ở mỗi bước. Mục tiêu của mỗi lần phân chia là chia dữ liệu sao cho biến mục tiêu trong các tập con thu được trở nên đồng nhất hơn (đối với phân loại, mỗi nút hướng đến độ thuần cao nhất có thể, chủ yếu chỉ chứa một lớp).

Cây quyết định **có khả năng diễn giải cao** -- có thể lần theo đường đi từ nút gốc đến nút lá để hiểu logic đằng sau một dự đoán (ví dụ: *"NẾU `service = telnet` VÀ `src_bytes > 1000` VÀ `failed_logins > 3` THÌ phân loại là tấn công"*). Điều này hữu ích trong an ninh mạng để giải thích lý do phát ra một cảnh báo. Cây có thể xử lý tự nhiên cả dữ liệu số lẫn dữ liệu phân loại và cần rất ít tiền xử lý (ví dụ: không cần chuẩn hóa đặc trưng).

Tuy nhiên, một cây quyết định đơn lẻ có thể dễ dàng overfit dữ liệu huấn luyện, đặc biệt nếu cây được phát triển quá sâu (có nhiều lần phân chia). Các kỹ thuật như pruning (giới hạn độ sâu của cây hoặc yêu cầu số lượng mẫu tối thiểu cho mỗi nút lá) thường được dùng để ngăn overfitting.

Cây quyết định có 3 thành phần chính:
- **Nút gốc**: Nút trên cùng của cây, biểu thị toàn bộ tập dữ liệu.
- **Nút bên trong**: Các nút biểu thị đặc trưng và quyết định dựa trên những đặc trưng đó.
- **Nút lá**: Các nút biểu thị kết quả cuối cùng hoặc dự đoán.

Cây có thể trông như sau:

```plaintext
          [Root Node]
              /   \
         [Node A]  [Node B]
          /   \      /   \
     [Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```

> [!TIP]
> *Ứng dụng trong an ninh mạng:* Cây quyết định đã được sử dụng trong các hệ thống phát hiện xâm nhập để rút ra **các quy tắc** nhận diện tấn công. Ví dụ, các IDS đời đầu dựa trên ID3/C4.5 sẽ tạo ra các quy tắc dễ đọc để phân biệt lưu lượng bình thường với lưu lượng độc hại. Chúng cũng được dùng trong phân tích malware để xác định một tệp có độc hại hay không dựa trên các thuộc tính của nó (kích thước tệp, entropy của section, các lệnh gọi API, v.v.). Tính rõ ràng của cây quyết định khiến chúng hữu ích khi cần tính minh bạch — nhà phân tích có thể kiểm tra cây để xác thực logic phát hiện.

#### **Các đặc điểm chính của Cây quyết định:**

-   **Loại bài toán:** Cả phân loại và hồi quy. Thường được dùng để phân loại tấn công và lưu lượng bình thường, v.v.

-   **Khả năng diễn giải:** Rất cao — các quyết định của mô hình có thể được trực quan hóa và hiểu như một tập hợp các quy tắc nếu-thì. Đây là một lợi thế lớn trong lĩnh vực bảo mật, giúp tăng độ tin cậy và xác minh hành vi của mô hình.

-   **Ưu điểm:** Có thể nắm bắt các mối quan hệ phi tuyến và tương tác giữa các đặc trưng (mỗi lần phân nhánh có thể được xem là một tương tác). Không cần chuẩn hóa đặc trưng hoặc mã hóa one-hot các biến phân loại — cây xử lý chúng theo cách riêng. Dự đoán nhanh (chỉ cần đi theo một nhánh trong cây).

-   **Hạn chế:** Dễ bị overfitting nếu không được kiểm soát (cây sâu có thể ghi nhớ tập huấn luyện). Chúng có thể không ổn định — những thay đổi nhỏ trong dữ liệu có thể dẫn đến cấu trúc cây khác. Khi dùng làm mô hình đơn lẻ, độ chính xác có thể không bằng các phương pháp tiên tiến hơn (các phương pháp ensemble như Random Forest thường cho hiệu quả tốt hơn nhờ giảm phương sai).

-   **Tìm điểm phân nhánh tốt nhất:**
  - **Gini Impurity**: Đo mức độ hỗn tạp của một nút. Gini impurity càng thấp thì điểm phân nhánh càng tốt. Công thức là:
  
  ```plaintext
  Gini = 1 - Σ(p_i^2)
  ```

  Trong đó `p_i` là tỷ lệ các mẫu thuộc lớp `i`.
  
  - **Entropy**: Đo mức độ bất định trong tập dữ liệu. Entropy thấp hơn cho thấy phép chia tốt hơn. Công thức là:

  ```plaintext
  Entropy = -Σ(p_i * log2(p_i))
  ```

  Trong đó `p_i` là tỷ lệ các mẫu thuộc lớp `i`.
  
  - **Mức tăng thông tin**: Mức giảm entropy hoặc độ hỗn tạp Gini sau khi phân tách. Mức tăng thông tin càng cao, phép phân tách càng tốt. Giá trị này được tính như sau:

  ```plaintext
  Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
  ```

Moreover, một cây kết thúc khi:
- Tất cả các mẫu trong một nút đều thuộc cùng một lớp. Điều này có thể dẫn đến quá khớp.
- Đạt đến độ sâu tối đa (được mã hóa cứng) của cây. Đây là một cách để ngăn quá khớp.
- Số lượng mẫu trong một nút thấp hơn một ngưỡng nhất định. Đây cũng là một cách để ngăn quá khớp.
- Mức tăng thông tin từ các lần phân tách tiếp theo thấp hơn một ngưỡng nhất định. Đây cũng là một cách để ngăn quá khớp.

<details>
<summary>Ví dụ -- Cây quyết định dùng để phát hiện xâm nhập:</summary>
Chúng ta sẽ huấn luyện một cây quyết định trên tập dữ liệu NSL-KDD để phân loại các kết nối mạng là *bình thường* hoặc *tấn công*. NSL-KDD là phiên bản cải tiến của tập dữ liệu KDD Cup 1999 kinh điển, với các đặc trưng như loại giao thức, dịch vụ, thời lượng, số lần đăng nhập thất bại, v.v., cùng nhãn cho biết loại tấn công hoặc "bình thường". Chúng ta sẽ ánh xạ tất cả các loại tấn công thành lớp "bất thường" (phân loại nhị phân: bình thường và bất thường). Sau khi huấn luyện, chúng ta sẽ đánh giá hiệu suất của cây trên tập kiểm tra.


```python
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1️⃣  NSL‑KDD column names (41 features + class + difficulty)
col_names = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
    "srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "class","difficulty_level"
]

# 2️⃣  Load data ➜ *headerless* CSV
train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# 3️⃣  Encode the 3 nominal features
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder().fit(pd.concat([df_train[col], df_test[col]]))
    df_train[col] = le.transform(df_train[col])
    df_test[col]  = le.transform(df_test[col])

# 4️⃣  Prepare X / y   (binary: 0 = normal, 1 = attack)
X_train = df_train.drop(columns=['class', 'difficulty_level'])
y_train = (df_train['class'].str.lower() != 'normal').astype(int)

X_test  = df_test.drop(columns=['class', 'difficulty_level'])
y_test  = (df_test['class'].str.lower() != 'normal').astype(int)

# 5️⃣  Train Decision‑Tree
clf = DecisionTreeClassifier(max_depth=10, random_state=42)
clf.fit(X_train, y_train)

# 6️⃣  Evaluate
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")


"""
Accuracy : 0.772
Precision: 0.967
Recall   : 0.621
F1‑score : 0.756
ROC AUC  : 0.758
"""
```

Trong ví dụ về cây quyết định này, chúng ta giới hạn độ sâu của cây ở mức 10 để tránh overfitting quá mức (tham số `max_depth=10`). Các chỉ số cho thấy cây phân biệt lưu lượng bình thường với lưu lượng tấn công tốt đến đâu. Recall cao nghĩa là phát hiện được hầu hết các cuộc tấn công (điều quan trọng đối với IDS), còn precision cao nghĩa là có ít cảnh báo giả. Cây quyết định thường đạt độ chính xác khá tốt trên dữ liệu có cấu trúc, nhưng một cây đơn lẻ có thể không đạt được hiệu suất tối ưu. Tuy vậy, *khả năng diễn giải* của mô hình là một ưu điểm lớn -- chúng ta có thể kiểm tra các nút phân tách của cây để xem, chẳng hạn, những đặc trưng nào (ví dụ: `service`, `src_bytes`, v.v.) có ảnh hưởng lớn nhất đến việc đánh dấu một kết nối là độc hại.

</details>

### Random Forests

Random Forest là một phương pháp **học tập tổ hợp** dựa trên cây quyết định để cải thiện hiệu suất. Random Forest huấn luyện nhiều cây quyết định (do đó có tên "rừng") rồi kết hợp kết quả của chúng để đưa ra dự đoán cuối cùng (đối với bài toán phân loại, thường là bỏ phiếu theo đa số). Hai ý tưởng chính trong Random Forest là **bagging** (bootstrap aggregating) và **tính ngẫu nhiên của đặc trưng**:

-   **Bagging:** Mỗi cây được huấn luyện trên một mẫu bootstrap ngẫu nhiên của dữ liệu huấn luyện (lấy mẫu có hoàn lại). Điều này tạo ra sự đa dạng giữa các cây.

-   **Tính ngẫu nhiên của đặc trưng:** Ở mỗi nút phân tách trong cây, một tập con đặc trưng ngẫu nhiên được chọn để xem xét phân tách (thay vì dùng tất cả đặc trưng). Điều này giúp các cây ít tương quan với nhau hơn.

Bằng cách lấy trung bình kết quả từ nhiều cây, Random Forest giảm phương sai mà một cây quyết định đơn lẻ có thể gặp phải. Nói đơn giản, từng cây riêng lẻ có thể bị overfit hoặc đưa ra kết quả nhiễu, nhưng nhiều cây đa dạng cùng bỏ phiếu sẽ giúp giảm các sai sót đó. Kết quả thường là mô hình có **độ chính xác cao hơn** và khả năng tổng quát hóa tốt hơn so với một cây quyết định đơn lẻ. Ngoài ra, Random Forest có thể ước tính độ quan trọng của đặc trưng (bằng cách tính mức giảm độ hỗn tạp trung bình do mỗi đặc trưng tạo ra khi phân tách).

Random Forest đã trở thành một **công cụ chủ lực trong an ninh mạng** cho các tác vụ như phát hiện xâm nhập, phân loại malware và phát hiện spam. Chúng thường hoạt động tốt ngay khi dùng mà không cần tinh chỉnh nhiều và có thể xử lý các tập đặc trưng lớn. Ví dụ, trong phát hiện xâm nhập, Random Forest có thể hoạt động tốt hơn một cây quyết định riêng lẻ bằng cách phát hiện nhiều mẫu tấn công tinh vi hơn với ít kết quả dương tính giả hơn. Nghiên cứu cho thấy Random Forest hoạt động hiệu quả so với các thuật toán khác trong việc phân loại tấn công trên các bộ dữ liệu như NSL-KDD và UNSW-NB15.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Đặc điểm chính của Random Forest:**

-   **Loại bài toán:** Chủ yếu là phân loại (cũng được dùng cho hồi quy). Rất phù hợp với dữ liệu có cấu trúc, nhiều chiều thường gặp trong nhật ký bảo mật.

-   **Khả năng diễn giải:** Thấp hơn so với một cây quyết định đơn lẻ -- bạn không thể dễ dàng trực quan hóa hoặc giải thích hàng trăm cây cùng lúc. Tuy nhiên, điểm độ quan trọng của đặc trưng cung cấp một số thông tin về những thuộc tính có ảnh hưởng lớn nhất.

-   **Ưu điểm:** Nhìn chung có độ chính xác cao hơn các mô hình cây đơn lẻ nhờ hiệu ứng tổ hợp. Có khả năng chống overfitting -- ngay cả khi từng cây riêng lẻ bị overfit, mô hình tổ hợp vẫn tổng quát hóa tốt hơn. Xử lý được cả đặc trưng dạng số và dạng phân loại, đồng thời có thể xử lý dữ liệu bị thiếu ở một mức độ nhất định. Mô hình cũng tương đối bền vững trước các giá trị ngoại lệ.

-   **Hạn chế:** Kích thước mô hình có thể lớn (nhiều cây, mỗi cây có thể có độ sâu lớn). Tốc độ dự đoán chậm hơn một cây đơn lẻ (vì phải tổng hợp kết quả của nhiều cây). Khả năng diễn giải thấp hơn -- dù biết các đặc trưng quan trọng, không dễ lần theo chính xác logic như một quy tắc đơn giản. Nếu tập dữ liệu có số chiều cực lớn và thưa, việc huấn luyện một Random Forest rất lớn có thể đòi hỏi nhiều tài nguyên tính toán.

-   **Quy trình huấn luyện:**
  1. **Lấy mẫu Bootstrap**: Lấy mẫu ngẫu nhiên có hoàn lại từ dữ liệu huấn luyện để tạo nhiều tập con (mẫu bootstrap).
  2. **Xây dựng cây**: Với mỗi mẫu bootstrap, xây dựng một cây quyết định bằng cách chọn ngẫu nhiên một tập con đặc trưng tại mỗi nút phân tách. Điều này tạo ra sự đa dạng giữa các cây.
  3. **Tổng hợp**: Với các tác vụ phân loại, dự đoán cuối cùng được đưa ra bằng cách lấy phiếu đa số từ dự đoán của tất cả các cây. Với các tác vụ hồi quy, dự đoán cuối cùng là trung bình các dự đoán của tất cả các cây.

<details>
<summary>Ví dụ -- Random Forest trong phát hiện xâm nhập (NSL-KDD):</summary>
Chúng ta sẽ dùng cùng bộ dữ liệu NSL-KDD (được gán nhãn nhị phân là bình thường hoặc bất thường) và huấn luyện một bộ phân loại Random Forest. Chúng ta kỳ vọng Random Forest sẽ hoạt động tốt ngang hoặc tốt hơn cây quyết định đơn lẻ, nhờ phép lấy trung bình trên mô hình tổ hợp giúp giảm phương sai. Chúng ta sẽ đánh giá mô hình bằng các chỉ số tương tự.


```python
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, roc_auc_score)

# ──────────────────────────────────────────────
# 1. LOAD DATA  ➜  files have **no header row**, so we
#                 pass `header=None` and give our own column names.
# ──────────────────────────────────────────────
col_names = [                       # 41 features + 2 targets
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# ──────────────────────────────────────────────
# 2. PRE‑PROCESSING
# ──────────────────────────────────────────────
# 2‑a) Encode the three categorical columns so that the model
#      receives integers instead of strings.
#      LabelEncoder gives an int to each unique value in the column: {'icmp':0, 'tcp':1, 'udp':2}
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder().fit(pd.concat([df_train[col], df_test[col]]))
    df_train[col] = le.transform(df_train[col])
    df_test[col]  = le.transform(df_test[col])

# 2‑b) Build feature matrix X  (drop target & difficulty)
X_train = df_train.drop(columns=['class', 'difficulty_level'])
X_test  = df_test.drop(columns=['class', 'difficulty_level'])

# 2‑c) Convert multi‑class labels to binary
#      label 0 → 'normal' traffic, label 1 → any attack
y_train = (df_train['class'].str.lower() != 'normal').astype(int)
y_test  = (df_test['class'].str.lower() != 'normal').astype(int)

# ──────────────────────────────────────────────
# 3. MODEL: RANDOM FOREST
# ──────────────────────────────────────────────
# • n_estimators = 100 ➜ build 100 different decision‑trees.
# • max_depth=None  ➜ let each tree grow until pure leaves
#                    (or until it hits other stopping criteria).
# • random_state=42 ➜ reproducible randomness.
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    random_state=42,
    bootstrap=True          # default: each tree is trained on a
                             # bootstrap sample the same size as
                             # the original training set.
    # max_samples           # ← you can set this (float or int) to
                             #     use a smaller % of samples per tree.
)

model.fit(X_train, y_train)

# ──────────────────────────────────────────────
# 4. EVALUATION
# ──────────────────────────────────────────────
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.770
Precision: 0.966
Recall:    0.618
F1-score:  0.754
ROC AUC:   0.962
"""
```

Cây random forest thường đạt kết quả tốt trong tác vụ phát hiện xâm nhập này. Ta có thể thấy các chỉ số như F1 hoặc AUC cải thiện so với cây quyết định đơn, đặc biệt là recall hoặc precision, tùy thuộc vào dữ liệu. Điều này phù hợp với nhận định rằng *"Random Forest (RF) là một bộ phân loại tổ hợp và hoạt động tốt so với các bộ phân loại truyền thống khác trong việc phân loại tấn công hiệu quả."*.<sup>[[6]](#references)</sup> Trong bối cảnh vận hành bảo mật, mô hình random forest có thể gắn cờ các cuộc tấn công đáng tin cậy hơn đồng thời giảm cảnh báo sai, nhờ lấy trung bình từ nhiều quy tắc quyết định. Độ quan trọng của đặc trưng từ forest có thể cho biết những đặc trưng mạng nào là dấu hiệu rõ nhất của các cuộc tấn công (ví dụ: một số dịch vụ mạng nhất định hoặc số lượng gói tin bất thường).

</details>

### Support Vector Machines (SVM)

Support Vector Machines là các mô hình học có giám sát mạnh mẽ, chủ yếu được dùng cho phân loại (và cả hồi quy dưới dạng SVR). SVM tìm **siêu phẳng phân tách tối ưu** để tối đa hóa biên giữa hai lớp. Chỉ một tập con các điểm huấn luyện (các "support vector" gần ranh giới nhất) quyết định vị trí của siêu phẳng này. Bằng cách tối đa hóa biên (khoảng cách giữa các support vector và siêu phẳng), SVM thường đạt khả năng tổng quát hóa tốt.<sup>[[8]](#references)</sup>

Điểm cốt yếu tạo nên sức mạnh của SVM là khả năng sử dụng **hàm kernel** để xử lý các mối quan hệ phi tuyến. Dữ liệu có thể được biến đổi ngầm sang không gian đặc trưng có số chiều cao hơn, nơi có thể tồn tại một bộ phân tách tuyến tính. Các kernel phổ biến gồm polynomial, radial basis function (RBF) và sigmoid. Ví dụ, nếu các lớp lưu lượng mạng không thể phân tách tuyến tính trong không gian đặc trưng thô, kernel RBF có thể ánh xạ chúng sang không gian nhiều chiều hơn, nơi SVM tìm được một ranh giới phân tách tuyến tính (tương ứng với ranh giới phi tuyến trong không gian ban đầu). Khả năng lựa chọn kernel linh hoạt cho phép SVM xử lý nhiều loại bài toán.

SVM nổi tiếng với hiệu quả trong các tình huống có không gian đặc trưng nhiều chiều (như dữ liệu văn bản hoặc chuỗi opcode của malware) và các trường hợp số lượng đặc trưng lớn so với số lượng mẫu. Chúng từng phổ biến trong nhiều ứng dụng an ninh mạng thời kỳ đầu, chẳng hạn như phân loại malware và phát hiện xâm nhập dựa trên bất thường vào những năm 2000, thường đạt độ chính xác cao.

Tuy nhiên, SVM không dễ mở rộng cho các tập dữ liệu rất lớn (độ phức tạp huấn luyện tăng nhanh hơn tuyến tính theo số lượng mẫu, và mức sử dụng bộ nhớ có thể cao vì mô hình có thể cần lưu trữ nhiều support vector). Trên thực tế, với các tác vụ như phát hiện xâm nhập mạng có hàng triệu bản ghi, SVM có thể quá chậm nếu không lấy mẫu con cẩn thận hoặc sử dụng các phương pháp xấp xỉ.

#### **Đặc điểm chính của SVM:**

-   **Loại bài toán:** Phân loại (nhị phân hoặc đa lớp thông qua one-vs-one/one-vs-rest) và các biến thể hồi quy. Thường được dùng trong phân loại nhị phân với ranh giới biên rõ ràng.

-   **Khả năng diễn giải:** Trung bình -- SVM không dễ diễn giải như cây quyết định hoặc logistic regression. Dù có thể xác định các điểm dữ liệu là support vector và phần nào nhận biết được những đặc trưng có thể ảnh hưởng (thông qua trọng số trong trường hợp dùng linear kernel), trên thực tế SVM (đặc biệt là khi dùng kernel phi tuyến) thường được xem là bộ phân loại hộp đen.

-   **Ưu điểm:** Hiệu quả trong không gian nhiều chiều; có thể mô hình hóa các ranh giới quyết định phức tạp bằng kernel trick; chống overfitting tốt nếu biên được tối đa hóa (đặc biệt khi chọn tham số regularization C phù hợp); hoạt động tốt ngay cả khi các lớp không cách nhau quá xa (tìm ranh giới dung hòa tốt nhất).

-   **Hạn chế:** **Tốn nhiều tài nguyên tính toán** với các tập dữ liệu lớn (cả huấn luyện lẫn dự đoán đều mở rộng kém khi dữ liệu tăng). Cần tinh chỉnh cẩn thận các tham số kernel và regularization (C, loại kernel, gamma cho RBF, v.v.). Không trực tiếp cung cấp đầu ra xác suất (mặc dù có thể dùng Platt scaling để tính xác suất). Ngoài ra, SVM có thể nhạy với việc chọn tham số kernel --- lựa chọn không phù hợp có thể dẫn đến underfit hoặc overfit.

*Các trường hợp sử dụng trong an ninh mạng:* SVM đã được dùng trong **phát hiện malware** (ví dụ: phân loại tệp dựa trên các đặc trưng đã trích xuất hoặc chuỗi opcode), **phát hiện bất thường mạng** (phân loại lưu lượng là bình thường hay độc hại) và **phát hiện phishing** (dùng các đặc trưng của URL). Chẳng hạn, SVM có thể sử dụng các đặc trưng của email (số lần xuất hiện của một số từ khóa, điểm uy tín của người gửi, v.v.) để phân loại email là phishing hay hợp lệ. SVM cũng được áp dụng cho **phát hiện xâm nhập** trên các tập đặc trưng như KDD, thường đạt độ chính xác cao nhưng tiêu tốn nhiều tài nguyên tính toán.

<details>
<summary>Ví dụ -- SVM dùng để phân loại Malware:</summary>
Ta sẽ lại dùng tập dữ liệu website phishing, lần này với SVM. Vì SVM có thể chạy chậm, nếu cần ta sẽ dùng một phần dữ liệu để huấn luyện (tập dữ liệu có khoảng 11k mẫu, mức này SVM có thể xử lý tương đối tốt). Ta sẽ dùng kernel RBF, một lựa chọn phổ biến cho dữ liệu phi tuyến, và bật tính năng ước lượng xác suất để tính ROC AUC.

```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, roc_auc_score)

# ─────────────────────────────────────────────────────────────
# 1️⃣  LOAD DATASET   (OpenML id 4534: “PhishingWebsites”)
#     • as_frame=True  ➜  returns a pandas DataFrame
# ─────────────────────────────────────────────────────────────
data = fetch_openml(data_id=4534, as_frame=True)   # or data_name="PhishingWebsites"
df   = data.frame
print(df.head())          # quick sanity‑check

# ─────────────────────────────────────────────────────────────
# 2️⃣  TARGET: 0 = legitimate, 1 = phishing
#     The raw column has values {1, 0, -1}:
#       1  → legitimate   → 0
#       0  &  -1          → phishing    → 1
# ─────────────────────────────────────────────────────────────
y = (df["Result"].astype(int) != 1).astype(int)
X = df.drop(columns=["Result"])

# Train / test split  (stratified keeps class proportions)
X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y)

# ─────────────────────────────────────────────────────────────
# 3️⃣  PRE‑PROCESS: Standardize features (mean‑0 / std‑1)
# ─────────────────────────────────────────────────────────────
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# ─────────────────────────────────────────────────────────────
# 4️⃣  MODEL: RBF‑kernel SVM
#     • C=1.0         (regularization strength)
#     • gamma='scale' (1 / [n_features × var(X)])
#     • probability=True  → enable predict_proba for ROC‑AUC
# ─────────────────────────────────────────────────────────────
clf = SVC(kernel="rbf", C=1.0, gamma="scale",
          probability=True, random_state=42)
clf.fit(X_train, y_train)

# ─────────────────────────────────────────────────────────────
# 5️⃣  EVALUATION
# ─────────────────────────────────────────────────────────────
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]   # P(class 1)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.956
Precision: 0.963
Recall   : 0.937
F1‑score : 0.950
ROC AUC  : 0.989
"""
```

Mô hình SVM sẽ đưa ra các chỉ số mà ta có thể so sánh với hồi quy logistic trên cùng tác vụ. Ta có thể thấy SVM đạt độ chính xác và AUC cao nếu các đặc trưng phân tách tốt dữ liệu. Ngược lại, nếu tập dữ liệu có nhiều nhiễu hoặc các lớp chồng lấn, SVM có thể không vượt trội đáng kể so với hồi quy logistic. Trên thực tế, SVM có thể cải thiện kết quả khi có các mối quan hệ phức tạp, phi tuyến giữa đặc trưng và lớp — kernel RBF có thể nắm bắt các ranh giới quyết định cong mà hồi quy logistic sẽ bỏ lỡ. Như với mọi mô hình, cần tinh chỉnh cẩn thận `C` (regularization) và các tham số kernel (chẳng hạn `gamma` cho RBF) để cân bằng độ chệch và phương sai.

</details>

#### Khác biệt giữa hồi quy logistic và SVM

| Khía cạnh | **Hồi quy Logistic** | **Support Vector Machines** |
|---|---|---|
| **Hàm mục tiêu** | Tối thiểu hóa **log-loss** (cross-entropy). | Tối đa hóa **margin** đồng thời tối thiểu hóa **hinge-loss**. |
| **Ranh giới quyết định** | Tìm **siêu phẳng khớp tốt nhất** để mô hình hóa _P(y\|x)_. | Tìm **siêu phẳng có margin lớn nhất** (khoảng cách lớn nhất đến các điểm gần nhất). |
| **Đầu ra** | **Xác suất** – cung cấp xác suất lớp đã hiệu chỉnh thông qua σ(w·x + b). | **Xác định** – trả về nhãn lớp; cần xử lý thêm để có xác suất (ví dụ: Platt scaling). |
| **Regularization** | L2 (mặc định) hoặc L1, trực tiếp cân bằng giữa khớp thiếu và khớp quá mức. | Tham số C đánh đổi giữa độ rộng margin và lỗi phân loại; các tham số kernel làm tăng độ phức tạp. |
| **Kernel / Phi tuyến** | Dạng cơ bản là **tuyến tính**; có thể thêm tính phi tuyến thông qua kỹ thuật tạo đặc trưng. | **Kỹ thuật kernel** tích hợp sẵn (RBF, poly, v.v.) cho phép mô hình hóa các ranh giới phức tạp trong không gian nhiều chiều. |
| **Khả năng mở rộng** | Giải bài toán tối ưu lồi trong **O(nd)**; xử lý tốt n rất lớn. | Quá trình huấn luyện có thể cần **O(n²–n³)** bộ nhớ/thời gian nếu không dùng bộ giải chuyên biệt; kém phù hợp với n cực lớn. |
| **Khả năng diễn giải** | **Cao** – trọng số cho thấy mức độ ảnh hưởng của đặc trưng; tỷ lệ odds dễ hiểu. | **Thấp** với kernel phi tuyến; support vector thưa nhưng không dễ giải thích. |
| **Độ nhạy với giá trị ngoại lệ** | Dùng log-loss trơn → ít nhạy hơn. | Hinge-loss với hard margin có thể **nhạy**; soft-margin (C) giúp giảm điều này. |
| **Trường hợp sử dụng phổ biến** | Chấm điểm tín dụng, rủi ro y tế, thử nghiệm A/B – khi **xác suất và khả năng giải thích** là quan trọng. | Phân loại ảnh/văn bản, tin sinh học – khi **ranh giới phức tạp** và **dữ liệu nhiều chiều** là quan trọng. |

* **Nếu cần xác suất đã hiệu chỉnh, khả năng diễn giải hoặc xử lý tập dữ liệu khổng lồ — hãy chọn hồi quy Logistic.**
* **Nếu cần một mô hình linh hoạt có thể nắm bắt các mối quan hệ phi tuyến mà không cần tạo đặc trưng thủ công — hãy chọn SVM (với kernel).**
* Cả hai đều tối ưu các hàm mục tiêu lồi, vì vậy **đảm bảo tìm được cực tiểu toàn cục**, nhưng kernel của SVM làm tăng số siêu tham số và chi phí tính toán.

### Naive Bayes

Naive Bayes là một nhóm **bộ phân loại xác suất** dựa trên việc áp dụng Định lý Bayes với giả định độc lập mạnh giữa các đặc trưng. Dù có giả định "ngây thơ" này, Naive Bayes thường hoạt động tốt đáng ngạc nhiên trong một số ứng dụng nhất định, đặc biệt là các ứng dụng liên quan đến văn bản hoặc dữ liệu phân loại, chẳng hạn như phát hiện thư rác.<sup>[[9]](#references)</sup>


#### Định lý Bayes

Định lý Bayes là nền tảng của các bộ phân loại Naive Bayes. Định lý này liên hệ xác suất có điều kiện với xác suất biên của các sự kiện ngẫu nhiên. Công thức là:

```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```

Where:
- `P(A|B)` là xác suất hậu nghiệm của lớp `A` khi biết đặc trưng `B`.
- `P(B|A)` là khả năng xảy ra của đặc trưng `B` khi biết lớp `A`.
- `P(A)` là xác suất tiên nghiệm của lớp `A`.
- `P(B)` là xác suất tiên nghiệm của đặc trưng `B`.

Ví dụ, nếu muốn phân loại một văn bản được viết bởi trẻ em hay người lớn, ta có thể dùng các từ trong văn bản làm đặc trưng. Dựa trên một số dữ liệu ban đầu, bộ phân loại Naive Bayes sẽ tính trước xác suất mỗi từ thuộc về từng lớp tiềm năng (trẻ em hoặc người lớn). Khi có văn bản mới, nó sẽ tính xác suất của từng lớp tiềm năng dựa trên các từ trong văn bản và chọn lớp có xác suất cao nhất.

Như bạn có thể thấy trong ví dụ này, bộ phân loại Naive Bayes rất đơn giản và nhanh, nhưng giả định rằng các đặc trưng độc lập với nhau, điều này không phải lúc nào cũng đúng với dữ liệu thực tế.


#### Các loại bộ phân loại Naive Bayes

Có một số loại bộ phân loại Naive Bayes, tùy thuộc vào loại dữ liệu và phân phối của các đặc trưng:
- **Gaussian Naive Bayes**: Giả định rằng các đặc trưng tuân theo phân phối Gaussian (chuẩn). Phù hợp với dữ liệu liên tục.
- **Multinomial Naive Bayes**: Giả định rằng các đặc trưng tuân theo phân phối đa thức. Phù hợp với dữ liệu rời rạc, chẳng hạn như số lần xuất hiện của từ trong phân loại văn bản.
- **Bernoulli Naive Bayes**: Giả định rằng các đặc trưng là nhị phân (0 hoặc 1). Phù hợp với dữ liệu nhị phân, chẳng hạn như sự hiện diện hoặc vắng mặt của từ trong phân loại văn bản.
- **Categorical Naive Bayes**: Giả định rằng các đặc trưng là biến phân loại. Phù hợp với dữ liệu phân loại, chẳng hạn như phân loại trái cây dựa trên màu sắc và hình dạng.


#### **Đặc điểm chính của Naive Bayes:**

-   **Loại bài toán:** Phân loại (nhị phân hoặc đa lớp). Thường được dùng cho các tác vụ phân loại văn bản trong cybersecurity (spam, phishing, v.v.).

-   **Khả năng diễn giải:** Trung bình -- không dễ diễn giải trực tiếp như cây quyết định, nhưng có thể kiểm tra các xác suất đã học (ví dụ: từ nào có khả năng xuất hiện cao nhất trong email spam so với email hợp lệ). Có thể hiểu cấu trúc của mô hình (xác suất của từng đặc trưng ứng với mỗi lớp) nếu cần.

-   **Ưu điểm:** Huấn luyện và dự đoán **rất nhanh**, ngay cả trên các tập dữ liệu lớn (tuyến tính theo số lượng mẫu * số lượng đặc trưng). Cần tương đối ít dữ liệu để ước tính xác suất đáng tin cậy, đặc biệt khi có làm trơn phù hợp. Mô hình này thường có độ chính xác đáng ngạc nhiên khi dùng làm baseline, nhất là khi các đặc trưng đóng góp bằng chứng độc lập cho lớp. Hoạt động tốt với dữ liệu có số chiều cao (ví dụ: hàng nghìn đặc trưng từ văn bản). Không cần tinh chỉnh phức tạp ngoài việc thiết lập tham số làm trơn.

-   **Hạn chế:** Giả định độc lập có thể làm giảm độ chính xác nếu các đặc trưng có tương quan cao. Ví dụ: trong dữ liệu mạng, các đặc trưng như `src_bytes` và `dst_bytes` có thể tương quan; Naive Bayes sẽ không nắm bắt được mối tương tác đó. Khi kích thước dữ liệu tăng rất lớn, các mô hình biểu đạt tốt hơn (như ensemble hoặc neural net) có thể vượt trội NB nhờ học được các mối phụ thuộc giữa đặc trưng. Ngoài ra, nếu cần kết hợp một số đặc trưng để nhận diện một cuộc tấn công (thay vì xét riêng từng đặc trưng), NB sẽ gặp khó khăn.

> [!TIP]
> *Trường hợp sử dụng trong cybersecurity:* Ứng dụng kinh điển là **phát hiện spam** -- Naive Bayes là cốt lõi của các bộ lọc spam thời kỳ đầu, sử dụng tần suất của một số token (từ, cụm từ, địa chỉ IP) để tính xác suất email là spam. Mô hình này cũng được dùng trong **phát hiện email phishing** và **phân loại URL**, trong đó sự hiện diện của một số từ khóa hoặc đặc điểm nhất định (như "login.php" trong URL hoặc `@` trong đường dẫn URL) góp phần làm tăng xác suất phishing. Trong phân tích malware, có thể hình dung một bộ phân loại Naive Bayes sử dụng sự hiện diện của một số lệnh gọi API hoặc quyền trong phần mềm để dự đoán phần mềm đó có phải malware hay không. Dù các thuật toán tiên tiến hơn thường cho hiệu quả tốt hơn, Naive Bayes vẫn là một baseline tốt nhờ tốc độ và sự đơn giản.

<details>
<summary>Ví dụ -- Naive Bayes để phát hiện Phishing:</summary>
Để minh họa Naive Bayes, chúng ta sẽ dùng Gaussian Naive Bayes trên tập dữ liệu xâm nhập NSL-KDD (với nhãn nhị phân). Gaussian NB sẽ coi mỗi đặc trưng tuân theo phân phối chuẩn trong từng lớp. Đây là lựa chọn tương đối thô vì nhiều đặc trưng mạng là rời rạc hoặc có phân phối lệch mạnh, nhưng ví dụ này cho thấy cách áp dụng NB với dữ liệu đặc trưng liên tục. Ta cũng có thể chọn Bernoulli NB trên một tập dữ liệu gồm các đặc trưng nhị phân (như một tập hợp cảnh báo đã được kích hoạt), nhưng ở đây chúng ta sẽ tiếp tục dùng NSL-KDD để nhất quán.

```python
import pandas as pd
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load NSL-KDD data
col_names = [                       # 41 features + 2 targets
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# 2. Preprocess (encode categorical features, prepare binary labels)
from sklearn.preprocessing import LabelEncoder
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
    df_train[col] = le.transform(df_train[col])
    df_test[col]  = le.transform(df_test[col])
X_train = df_train.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_train = df_train['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)
X_test  = df_test.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_test  = df_test['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)

# 3. Train Gaussian Naive Bayes
model = GaussianNB()
model.fit(X_train, y_train)

# 4. Evaluate on test set
y_pred = model.predict(X_test)
# For ROC AUC, need probability of class 1:
y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1-score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.450
Precision: 0.937
Recall:    0.037
F1-score:  0.071
ROC AUC:   0.867
"""
```

This code huấn luyện bộ phân loại Naive Bayes để phát hiện các cuộc tấn công. Naive Bayes sẽ tính những xác suất như `P(service=http | Attack)` và `P(Service=http | Normal)` dựa trên dữ liệu huấn luyện, với giả định các đặc trưng độc lập với nhau. Sau đó, thuật toán dùng các xác suất này để phân loại những kết nối mới là bình thường hay tấn công, dựa trên các đặc trưng quan sát được. Hiệu suất của NB trên NSL-KDD có thể không cao bằng các mô hình tiên tiến hơn (vì giả định các đặc trưng độc lập bị vi phạm), nhưng thường vẫn khá tốt và có ưu điểm là cực kỳ nhanh. Trong các tình huống như lọc email theo thời gian thực hoặc phân loại sơ bộ URL, mô hình Naive Bayes có thể nhanh chóng đánh dấu những trường hợp rõ ràng là độc hại mà chỉ cần ít tài nguyên.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors là một trong những thuật toán machine learning đơn giản nhất. Đây là phương pháp **phi tham số, dựa trên mẫu**, đưa ra dự đoán dựa trên mức độ tương đồng với các ví dụ trong tập huấn luyện. Ý tưởng phân loại là: để phân loại một điểm dữ liệu mới, tìm **k** điểm gần nhất trong dữ liệu huấn luyện ("các láng giềng gần nhất" của nó), rồi gán lớp chiếm đa số trong số các láng giềng đó. "Độ gần" được xác định bằng một metric khoảng cách, thường là khoảng cách Euclid đối với dữ liệu dạng số (có thể dùng các khoảng cách khác cho những loại đặc trưng hoặc bài toán khác nhau).<sup>[[10]](#references)</sup>

K-NN *không cần huấn luyện tường minh* -- giai đoạn "huấn luyện" chỉ đơn giản là lưu trữ tập dữ liệu. Mọi việc diễn ra khi truy vấn (dự đoán): thuật toán phải tính khoảng cách từ điểm truy vấn đến tất cả các điểm huấn luyện để tìm những điểm gần nhất. Điều này khiến thời gian dự đoán **tăng tuyến tính theo số lượng mẫu huấn luyện**, có thể gây tốn kém với các tập dữ liệu lớn. Vì vậy, k-NN phù hợp nhất với các tập dữ liệu nhỏ hơn hoặc những tình huống có thể đánh đổi bộ nhớ và tốc độ để lấy sự đơn giản.

Dù đơn giản, k-NN có thể mô hình hóa các ranh giới quyết định rất phức tạp (vì về bản chất, ranh giới quyết định có thể mang bất kỳ hình dạng nào do phân bố các ví dụ quy định). Thuật toán thường hoạt động tốt khi ranh giới quyết định rất bất quy tắc và có nhiều dữ liệu -- về cơ bản, để dữ liệu "tự lên tiếng". Tuy nhiên, trong không gian nhiều chiều, các metric khoảng cách có thể trở nên kém ý nghĩa hơn (lời nguyền số chiều), và phương pháp này có thể gặp khó khăn nếu không có số lượng mẫu khổng lồ.

*Trường hợp sử dụng trong an ninh mạng:* k-NN đã được áp dụng để phát hiện bất thường -- ví dụ, một hệ thống phát hiện xâm nhập có thể gắn nhãn một sự kiện mạng là độc hại nếu phần lớn các láng giềng gần nhất của nó (những sự kiện trước đó) là độc hại. Nếu lưu lượng bình thường tạo thành các cụm còn các cuộc tấn công là những điểm ngoại lệ, cách tiếp cận K-NN (với k=1 hoặc k nhỏ) về cơ bản sẽ thực hiện **phát hiện bất thường bằng láng giềng gần nhất**. K-NN cũng được dùng để phân loại các họ malware bằng vector đặc trưng nhị phân: một tệp mới có thể được phân loại vào một họ malware nhất định nếu nó rất gần (trong không gian đặc trưng) với các mẫu đã biết thuộc họ đó. Trên thực tế, k-NN không phổ biến bằng các thuật toán có khả năng mở rộng tốt hơn, nhưng về mặt khái niệm thì khá dễ hiểu và đôi khi được dùng làm mô hình cơ sở hoặc cho các bài toán quy mô nhỏ.

#### **Đặc điểm chính của k-NN:**

-   **Loại bài toán:** Phân loại (cũng có các biến thể hồi quy). Đây là phương pháp *học lười* -- không cần khớp mô hình tường minh.

-   **Khả năng diễn giải:** Thấp đến trung bình -- không có mô hình tổng quát hay lời giải thích ngắn gọn, nhưng có thể diễn giải kết quả bằng cách xem xét các láng giềng gần nhất đã ảnh hưởng đến quyết định (ví dụ: "luồng mạng này được phân loại là độc hại vì nó tương tự 3 luồng độc hại đã biết này"). Do đó, lời giải thích có thể dựa trên ví dụ.

-   **Ưu điểm:** Rất đơn giản để triển khai và hiểu. Không đưa ra giả định nào về phân bố dữ liệu (phi tham số). Có thể xử lý tự nhiên các bài toán nhiều lớp. Thuật toán **thích ứng** theo nghĩa ranh giới quyết định có thể rất phức tạp và được định hình bởi phân bố dữ liệu.

-   **Hạn chế:** Dự đoán có thể chậm với các tập dữ liệu lớn (phải tính nhiều khoảng cách). Tốn bộ nhớ -- thuật toán lưu trữ toàn bộ dữ liệu huấn luyện. Hiệu suất giảm trong không gian đặc trưng nhiều chiều vì mọi điểm có xu hướng gần như cách đều nhau (khiến khái niệm "gần nhất" kém ý nghĩa hơn). Cần chọn *k* (số lượng láng giềng) phù hợp -- k quá nhỏ có thể gây nhiễu, k quá lớn có thể bao gồm các điểm không liên quan thuộc lớp khác. Ngoài ra, cần điều chỉnh tỷ lệ các đặc trưng cho phù hợp vì phép tính khoảng cách nhạy với tỷ lệ.

<details>
<summary>Ví dụ -- k-NN để phát hiện Phishing:</summary>

Ta sẽ tiếp tục dùng NSL-KDD (phân loại nhị phân). Vì k-NN đòi hỏi nhiều tính toán, ta sẽ dùng một tập con dữ liệu huấn luyện để phần minh họa này có thể thực hiện được. Chẳng hạn, ta sẽ chọn 20,000 mẫu huấn luyện trong tổng số 125k và dùng k=5 láng giềng. Sau khi huấn luyện (thực chất chỉ là lưu trữ dữ liệu), ta sẽ đánh giá trên tập kiểm tra. Ta cũng sẽ chuẩn hóa các đặc trưng để tính khoảng cách, nhằm đảm bảo không có đặc trưng nào chi phối chỉ vì tỷ lệ của nó.

```python
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load NSL-KDD and preprocess similarly
col_names = [                       # 41 features + 2 targets
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

from sklearn.preprocessing import LabelEncoder
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
    df_train[col] = le.transform(df_train[col])
    df_test[col]  = le.transform(df_test[col])
X = df_train.drop(columns=['class', 'difficulty_level'], errors='ignore')
y = df_train['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)
# Use a random subset of the training data for K-NN (to reduce computation)
X_train = X.sample(n=20000, random_state=42)
y_train = y[X_train.index]
# Use the full test set for evaluation
X_test = df_test.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_test = df_test['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)

# 2. Feature scaling for distance-based model
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# 3. Train k-NN classifier (store data)
model = KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
model.fit(X_train, y_train)

# 4. Evaluate on test set
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1-score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.780
Precision: 0.972
Recall:    0.632
F1-score:  0.766
ROC AUC:   0.837
"""
```

Mô hình k-NN sẽ phân loại một kết nối bằng cách xem xét 5 kết nối gần nhất trong tập con của tập huấn luyện. Ví dụ, nếu 4 trong số các láng giềng đó là các cuộc tấn công (bất thường) và 1 là bình thường, kết nối mới sẽ được phân loại là một cuộc tấn công. Hiệu suất có thể khá tốt, dù thường không cao bằng Random Forest hoặc SVM được tinh chỉnh tốt trên cùng dữ liệu. Tuy nhiên, đôi khi k-NN có thể vượt trội khi phân bố lớp rất bất quy tắc và phức tạp -- về cơ bản là sử dụng phương thức tra cứu dựa trên bộ nhớ. Trong an ninh mạng, k-NN (với k=1 hoặc k nhỏ) có thể được dùng để phát hiện các mẫu tấn công đã biết dựa trên ví dụ, hoặc làm thành phần trong các hệ thống phức tạp hơn (ví dụ: phân cụm rồi phân loại dựa trên việc thuộc cụm nào).
</details>

### Gradient Boosting Machines (ví dụ: XGBoost)

Gradient Boosting Machines là một trong những thuật toán mạnh nhất dành cho dữ liệu có cấu trúc. **Gradient boosting** là kỹ thuật xây dựng một tổ hợp các mô hình học yếu (thường là cây quyết định) theo trình tự, trong đó mỗi mô hình mới sửa các lỗi của tổ hợp trước đó. Không giống bagging (Random Forests), vốn xây dựng các cây song song rồi lấy trung bình, boosting xây dựng cây *lần lượt*, mỗi cây tập trung nhiều hơn vào các mẫu mà những cây trước đó dự đoán sai.<sup>[[11]](#references)</sup>

Các thư viện phổ biến nhất trong những năm gần đây là **XGBoost**, **LightGBM** và **CatBoost**; tất cả đều là thư viện cây quyết định gradient boosting (GBDT). Chúng đã đạt được thành công lớn trong các cuộc thi và ứng dụng machine learning, thường **đạt hiệu suất tiên tiến nhất trên các tập dữ liệu dạng bảng**. Trong an ninh mạng, các nhà nghiên cứu và chuyên gia đã sử dụng cây gradient boosting cho những tác vụ như **phát hiện malware** (dùng các đặc trưng trích xuất từ tệp hoặc hành vi khi chạy) và **phát hiện xâm nhập mạng**. Ví dụ, một mô hình gradient boosting có thể kết hợp nhiều quy tắc yếu (cây) như "nếu có nhiều gói SYN và cổng bất thường -> có khả năng là quét" thành một bộ phát hiện tổng hợp mạnh, có khả năng nhận biết nhiều mẫu tinh vi.

Vì sao cây boosted lại hiệu quả đến vậy? Mỗi cây trong chuỗi được huấn luyện dựa trên *sai số phần dư* (gradient) của các dự đoán từ tổ hợp hiện tại. Nhờ vậy, mô hình dần **"boost"** những khía cạnh mà nó còn yếu. Việc sử dụng cây quyết định làm mô hình cơ sở giúp mô hình cuối cùng nắm bắt được các tương tác phức tạp và quan hệ phi tuyến. Ngoài ra, boosting vốn có một dạng điều chuẩn tích hợp: bằng cách thêm nhiều cây nhỏ (và dùng learning rate để điều chỉnh mức đóng góp của chúng), mô hình thường khái quát hóa tốt mà không bị overfitting quá mức, miễn là chọn tham số phù hợp.

#### **Các đặc điểm chính của Gradient Boosting:**

-   **Loại bài toán:** Chủ yếu là phân loại và hồi quy. Trong bảo mật, thường là phân loại (ví dụ: phân loại kết nối hoặc tệp thành hai nhóm). Mô hình xử lý được bài toán nhị phân, đa lớp (với hàm mất mát phù hợp), và cả bài toán xếp hạng.

-   **Khả năng diễn giải:** Thấp đến trung bình. Một cây boosted đơn lẻ có thể nhỏ, nhưng toàn bộ mô hình có thể gồm hàng trăm cây nên không thể diễn giải trực tiếp bằng con người. Tuy nhiên, giống Random Forest, mô hình có thể cung cấp điểm số mức độ quan trọng của đặc trưng; các công cụ như SHAP (SHapley Additive exPlanations) cũng có thể được dùng để diễn giải phần nào các dự đoán riêng lẻ.

-   **Ưu điểm:** Thường là thuật toán **có hiệu suất tốt nhất** cho dữ liệu có cấu trúc/dạng bảng. Có thể phát hiện các mẫu và tương tác phức tạp. Có nhiều tham số để tinh chỉnh (số lượng cây, độ sâu của cây, learning rate, các hạng tử điều chuẩn) nhằm điều chỉnh độ phức tạp của mô hình và ngăn overfitting. Các triển khai hiện đại được tối ưu hóa về tốc độ (ví dụ, XGBoost sử dụng thông tin gradient bậc hai và cấu trúc dữ liệu hiệu quả). Có xu hướng xử lý dữ liệu mất cân bằng tốt hơn khi kết hợp với hàm mất mát phù hợp hoặc điều chỉnh trọng số mẫu.

-   **Hạn chế:** Khó tinh chỉnh hơn các mô hình đơn giản; quá trình huấn luyện có thể chậm nếu cây sâu hoặc số lượng cây lớn (dù thường vẫn nhanh hơn huấn luyện mạng nơ-ron sâu tương đương trên cùng dữ liệu). Mô hình có thể bị overfit nếu không được tinh chỉnh (ví dụ: quá nhiều cây sâu mà không có đủ điều chuẩn). Do có nhiều siêu tham số, việc sử dụng gradient boosting hiệu quả có thể đòi hỏi nhiều chuyên môn hoặc thử nghiệm hơn. Ngoài ra, giống các phương pháp dựa trên cây, mô hình không thể tự xử lý dữ liệu thưa, nhiều chiều hiệu quả bằng mô hình tuyến tính hoặc Naive Bayes (dù vẫn có thể áp dụng, chẳng hạn trong phân loại văn bản, nhưng có thể không phải lựa chọn hàng đầu nếu không có kỹ thuật tạo đặc trưng).

> [!TIP]
> *Các trường hợp sử dụng trong an ninh mạng:* Hầu như ở bất cứ đâu có thể dùng cây quyết định hoặc random forest, mô hình gradient boosting có thể đạt độ chính xác cao hơn. Ví dụ, các cuộc thi **phát hiện malware của Microsoft** đã sử dụng rộng rãi XGBoost trên các đặc trưng được tạo từ tệp nhị phân. Nghiên cứu về **phát hiện xâm nhập mạng** thường ghi nhận kết quả hàng đầu với GBDT (ví dụ: XGBoost trên các tập dữ liệu CIC-IDS2017 hoặc UNSW-NB15). Các mô hình này có thể sử dụng nhiều loại đặc trưng (loại giao thức, tần suất của một số sự kiện, đặc trưng thống kê của lưu lượng mạng, v.v.) và kết hợp chúng để phát hiện mối đe dọa. Trong phát hiện phishing, gradient boosting có thể kết hợp các đặc trưng từ vựng của URL, đặc trưng về uy tín của tên miền và đặc trưng nội dung trang để đạt độ chính xác rất cao. Phương pháp tổ hợp giúp bao quát nhiều trường hợp ngoại lệ và sắc thái tinh tế trong dữ liệu.

<details>
<summary>Ví dụ -- XGBoost để phát hiện phishing:</summary>
Chúng ta sẽ dùng một bộ phân loại gradient boosting trên tập dữ liệu phishing. Để giữ cho ví dụ đơn giản và độc lập, chúng ta sẽ dùng `sklearn.ensemble.GradientBoostingClassifier` (một triển khai chậm hơn nhưng dễ hiểu). Thông thường, có thể dùng các thư viện `xgboost` hoặc `lightgbm` để đạt hiệu suất tốt hơn và có thêm tính năng. Chúng ta sẽ huấn luyện mô hình và đánh giá tương tự như trước.

```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1️⃣ Load the “Phishing Websites” data directly from OpenML
data = fetch_openml(data_id=4534, as_frame=True)   # or data_name="PhishingWebsites"
df   = data.frame

# 2️⃣ Separate features/target & make sure everything is numeric
X = df.drop(columns=["Result"])
y = df["Result"].astype(int).apply(lambda v: 1 if v == 1 else 0)  # map {-1,1} → {0,1}

# (If any column is still object‑typed, coerce it to numeric.)
X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

# 3️⃣ Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X.values, y, test_size=0.20, random_state=42
)

# 4️⃣ Gradient Boosting model
model = GradientBoostingClassifier(
    n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42
)
model.fit(X_train, y_train)

# 5️⃣ Evaluation
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.951
Precision: 0.949
Recall:    0.965
F1‑score:  0.957
ROC AUC:   0.990
"""
```

Mô hình gradient boosting có khả năng đạt độ chính xác và AUC rất cao trên tập dữ liệu phishing này (với dữ liệu như vậy, các mô hình này thường có thể vượt 95% độ chính xác nếu được tinh chỉnh phù hợp, như đã thấy trong các tài liệu nghiên cứu. Điều này cho thấy vì sao GBDT được xem là *"mô hình tiên tiến nhất cho tập dữ liệu dạng bảng"* -- chúng thường vượt trội hơn các thuật toán đơn giản hơn nhờ khả năng nắm bắt các mẫu phức tạp.<sup>[[11]](#references)</sup> Trong lĩnh vực an ninh mạng, điều này có thể giúp phát hiện nhiều trang phishing hoặc cuộc tấn công hơn và bỏ sót ít trường hợp hơn. Tất nhiên, cần thận trọng với hiện tượng overfitting -- thông thường, khi phát triển mô hình để triển khai, chúng ta sẽ dùng các kỹ thuật như cross-validation và theo dõi hiệu suất trên tập validation.

</details>

### Kết hợp mô hình: Ensemble Learning và Stacking

Ensemble learning là chiến lược **kết hợp nhiều mô hình** để cải thiện hiệu suất tổng thể. Chúng ta đã thấy một số phương pháp ensemble cụ thể: Random Forest (ensemble gồm các cây thông qua bagging) và Gradient Boosting (ensemble gồm các cây thông qua boosting tuần tự). Tuy nhiên, cũng có thể tạo ensemble theo những cách khác, chẳng hạn như **voting ensemble** hoặc **stacked generalization (stacking)**. Ý tưởng chính là các mô hình khác nhau có thể nắm bắt những mẫu khác nhau hoặc có những điểm yếu khác nhau; bằng cách kết hợp chúng, chúng ta có thể **bù đắp lỗi của mỗi mô hình bằng thế mạnh của mô hình khác**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** Trong một voting classifier đơn giản, chúng ta huấn luyện nhiều mô hình đa dạng (chẳng hạn logistic regression, decision tree và SVM), rồi để chúng bỏ phiếu cho dự đoán cuối cùng (classification dùng đa số phiếu). Nếu gán trọng số cho các phiếu (ví dụ: trọng số cao hơn cho những mô hình chính xác hơn), ta có voting scheme có trọng số. Cách này thường cải thiện hiệu suất khi các mô hình riêng lẻ hoạt động khá tốt và độc lập với nhau -- ensemble làm giảm nguy cơ một mô hình mắc lỗi, vì các mô hình khác có thể sửa lỗi đó. Cách này giống như có một hội đồng chuyên gia thay vì chỉ có một ý kiến.

-   **Stacking (Stacked Ensemble):** Stacking tiến thêm một bước. Thay vì chỉ bỏ phiếu đơn giản, phương pháp này huấn luyện một **meta-model** để **học cách kết hợp tốt nhất các dự đoán** từ các mô hình cơ sở. Ví dụ, bạn huấn luyện 3 classifier khác nhau (base learner), rồi đưa đầu ra (hoặc xác suất) của chúng làm feature cho một meta-classifier (thường là mô hình đơn giản như logistic regression), để mô hình này học cách kết hợp chúng tối ưu. Meta-model được huấn luyện trên tập validation hoặc thông qua cross-validation để tránh overfitting. Stacking thường có thể vượt trội hơn voting đơn giản vì nó học được *nên tin cậy mô hình nào hơn trong từng trường hợp*. Trong an ninh mạng, một mô hình có thể phát hiện network scan tốt hơn, trong khi mô hình khác phát hiện malware beaconing tốt hơn; stacking model có thể học cách dựa vào từng mô hình phù hợp.

Các ensemble, dù dùng voting hay stacking, thường **tăng độ chính xác** và độ vững chắc. Nhược điểm là độ phức tạp tăng và đôi khi khả năng diễn giải giảm (dù một số phương pháp ensemble như lấy trung bình các decision tree vẫn có thể cung cấp một số thông tin, chẳng hạn feature importance). Trong thực tế, nếu các ràng buộc vận hành cho phép, sử dụng ensemble có thể giúp tăng tỷ lệ phát hiện. Nhiều giải pháp chiến thắng trong các thử thách an ninh mạng (và các cuộc thi Kaggle nói chung) sử dụng kỹ thuật ensemble để cải thiện thêm hiệu suất.

<details>
<summary>Ví dụ -- Voting Ensemble để phát hiện phishing:</summary>
Để minh họa model stacking, hãy kết hợp một vài mô hình đã thảo luận trên tập dữ liệu phishing. Chúng ta sẽ dùng logistic regression, decision tree và k-NN làm base learner, đồng thời dùng Random Forest làm meta-learner để tổng hợp các dự đoán của chúng. Meta-learner sẽ được huấn luyện trên đầu ra của các base learner (bằng cross-validation trên tập training). Chúng ta kỳ vọng mô hình stacking sẽ hoạt động ngang bằng hoặc tốt hơn đôi chút so với các mô hình riêng lẻ.

```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import StackingClassifier, RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, roc_auc_score)

# ──────────────────────────────────────────────
# 1️⃣  LOAD DATASET (OpenML id 4534)
# ──────────────────────────────────────────────
data = fetch_openml(data_id=4534, as_frame=True)     # “PhishingWebsites”
df   = data.frame

# Target mapping:  1 → legitimate (0),   0/‑1 → phishing (1)
y = (df["Result"].astype(int) != 1).astype(int)
X = df.drop(columns=["Result"])

# Train / test split (stratified to keep class balance)
X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y)

# ──────────────────────────────────────────────
# 2️⃣  DEFINE BASE LEARNERS
#     • LogisticRegression and k‑NN need scaling ➜ wrap them
#       in a Pipeline(StandardScaler → model) so that scaling
#       happens inside each CV fold of StackingClassifier.
# ──────────────────────────────────────────────
base_learners = [
    ('lr',  make_pipeline(StandardScaler(),
                          LogisticRegression(max_iter=1000,
                                             solver='lbfgs',
                                             random_state=42))),
    ('dt',  DecisionTreeClassifier(max_depth=5, random_state=42)),
    ('knn', make_pipeline(StandardScaler(),
                          KNeighborsClassifier(n_neighbors=5)))
]

# Meta‑learner (level‑2 model)
meta_learner = RandomForestClassifier(n_estimators=50, random_state=42)

stack_model = StackingClassifier(
    estimators      = base_learners,
    final_estimator = meta_learner,
    cv              = 5,        # 5‑fold CV to create meta‑features
    passthrough     = False     # only base learners’ predictions go to meta‑learner
)

# ──────────────────────────────────────────────
# 3️⃣  TRAIN ENSEMBLE
# ──────────────────────────────────────────────
stack_model.fit(X_train, y_train)

# ──────────────────────────────────────────────
# 4️⃣  EVALUATE
# ──────────────────────────────────────────────
y_pred = stack_model.predict(X_test)
y_prob = stack_model.predict_proba(X_test)[:, 1]   # P(phishing)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.954
Precision: 0.951
Recall   : 0.946
F1‑score : 0.948
ROC AUC  : 0.992
"""
```
Ensemble xếp chồng tận dụng những điểm mạnh bổ trợ cho nhau của các mô hình cơ sở. Chẳng hạn, logistic regression có thể xử lý các khía cạnh tuyến tính của dữ liệu, decision tree có thể nắm bắt các tương tác cụ thể giống như quy tắc, còn k-NN có thể hoạt động tốt trong các vùng lân cận cục bộ của không gian đặc trưng. Meta-model (ở đây là random forest) có thể học cách gán trọng số cho các đầu vào này. Các chỉ số thu được thường cho thấy sự cải thiện (dù nhỏ) so với chỉ số của từng mô hình riêng lẻ. Trong ví dụ phishing của chúng ta, nếu riêng logistic đạt F1 là 0.95 và tree đạt 0.94, thì mô hình kết hợp có thể đạt 0.96 nhờ tận dụng những điểm mà mỗi mô hình mắc lỗi.

Các phương pháp ensemble như thế này minh họa nguyên lý *"kết hợp nhiều mô hình thường giúp khái quát hóa tốt hơn"*.<sup>[[12]](#references)</sup> Trong an ninh mạng, có thể triển khai phương pháp này bằng cách sử dụng nhiều engine phát hiện (một engine có thể dựa trên quy tắc, một engine dùng machine learning, một engine dựa trên phát hiện bất thường), rồi thêm một lớp tổng hợp các cảnh báo của chúng -- về bản chất là một dạng ensemble -- để đưa ra quyết định cuối cùng với độ tin cậy cao hơn. Khi triển khai các hệ thống như vậy, cần cân nhắc độ phức tạp tăng thêm và đảm bảo ensemble không trở nên quá khó quản lý hoặc giải thích. Tuy nhiên, xét về độ chính xác, ensemble và stacking là những công cụ mạnh mẽ giúp cải thiện hiệu suất mô hình.

</details>

Các phương pháp tiếp cận neural network được mô tả trong [trang deep-learning](AI-Deep-Learning.md) có thể bổ trợ cho những mô hình cổ điển này trong việc phát hiện xâm nhập khi tập dữ liệu và ngân sách tính toán đủ đáp ứng độ phức tạp tăng thêm.<sup>[[13]](#references)</sup>

## References

- [1] [AI và Machine Learning trong an ninh mạng - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Giải thích về Linear Regression - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Phân loại các cuộc tấn công phishing và website bằng Machine Learning và nhiều tập dữ liệu (Phân tích so sánh)"](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Phát hiện tấn công từ chối dịch vụ bằng bộ phân loại Random Forest với Information Gain"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Phân tích hiệu suất của các mô hình machine learning cho hệ thống phát hiện xâm nhập bằng kỹ thuật lựa chọn đặc trưng Gini Impurity-based Weighted Random Forest (GIWRF)"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Support Vector Machine là gì? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Lọc spam bằng Naive Bayes - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [k-Nearest Neighbors (KNN) là gì? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [Giải mã GBDT: Cách LightGBM, XGBoost và CatBoost hoạt động - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: Cải thiện hiệu suất mô hình bằng cách kết hợp các điểm mạnh - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Deep Learning cải thiện hệ thống phát hiện xâm nhập như thế nào](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
