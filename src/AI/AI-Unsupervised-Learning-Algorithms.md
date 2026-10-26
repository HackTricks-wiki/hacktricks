# Các thuật toán học không giám sát

{{#include ../banners/hacktricks-training.md}}

## Học không giám sát

Học không giám sát là một loại machine learning trong đó mô hình được huấn luyện trên dữ liệu không có nhãn. Mục tiêu là tìm ra các mẫu, cấu trúc hoặc mối quan hệ trong dữ liệu. Không giống như học có giám sát, trong đó mô hình học từ các ví dụ có nhãn, các thuật toán học không giám sát hoạt động với dữ liệu chưa gán nhãn.
Học không giám sát thường được dùng cho các tác vụ như phân cụm, giảm chiều dữ liệu và phát hiện bất thường. Phương pháp này có thể giúp khám phá các mẫu ẩn trong dữ liệu, nhóm các mục tương tự lại với nhau hoặc giảm độ phức tạp của dữ liệu trong khi vẫn giữ lại các đặc trưng thiết yếu.


### Phân cụm K-Means

K-Means là thuật toán phân cụm dựa trên centroid, chia dữ liệu thành K cụm bằng cách gán mỗi điểm dữ liệu vào trung bình cụm gần nhất. Thuật toán hoạt động như sau:
1. **Khởi tạo**: Chọn K tâm cụm ban đầu (centroid), thường là ngẫu nhiên hoặc bằng các phương pháp thông minh hơn như k-means++
2. **Gán**: Gán mỗi điểm dữ liệu cho centroid gần nhất dựa trên một thước đo khoảng cách (ví dụ: khoảng cách Euclid).
3. **Cập nhật**: Tính lại các centroid bằng cách lấy trung bình tất cả điểm dữ liệu được gán cho từng cụm.
4. **Lặp lại**: Lặp lại các bước 2–3 cho đến khi các điểm được gán vào cụm ổn định (centroid không còn di chuyển đáng kể).

> [!TIP]
> *Các trường hợp sử dụng trong an ninh mạng:* K-Means được dùng để phát hiện xâm nhập bằng cách phân cụm các sự kiện mạng. Ví dụ, các nhà nghiên cứu đã áp dụng K-Means vào bộ dữ liệu xâm nhập KDD Cup 99 và nhận thấy thuật toán phân chia lưu lượng thành các cụm bình thường và tấn công rất hiệu quả. Trong thực tế, chuyên gia bảo mật có thể phân cụm các mục nhật ký hoặc dữ liệu hành vi người dùng để tìm các nhóm hoạt động tương tự; bất kỳ điểm nào không thuộc một cụm có cấu trúc rõ ràng đều có thể là dấu hiệu của bất thường (ví dụ: một biến thể malware mới tạo thành một cụm nhỏ riêng). K-Means cũng có thể hỗ trợ phân loại các họ malware bằng cách nhóm các tệp nhị phân dựa trên hồ sơ hành vi hoặc vector đặc trưng.

#### Lựa chọn K
Số lượng cụm (K) là một siêu tham số cần được xác định trước khi chạy thuật toán. Các kỹ thuật như Elbow Method hoặc Silhouette Score có thể giúp xác định giá trị K phù hợp bằng cách đánh giá hiệu suất phân cụm:

- **Elbow Method**: Vẽ biểu đồ tổng bình phương khoảng cách từ mỗi điểm đến centroid của cụm được gán cho điểm đó theo giá trị K. Tìm điểm “khuỷu tay”, nơi tốc độ giảm thay đổi đột ngột, cho biết số lượng cụm phù hợp.
- **Silhouette Score**: Tính silhouette score cho các giá trị K khác nhau. Silhouette score càng cao thì các cụm càng được xác định rõ.

#### Các giả định và hạn chế

K-Means giả định rằng **các cụm có dạng hình cầu và kích thước bằng nhau**, nhưng điều này có thể không đúng với mọi bộ dữ liệu. Thuật toán nhạy với vị trí ban đầu của các centroid và có thể hội tụ về cực tiểu cục bộ. Ngoài ra, K-Means không phù hợp với các bộ dữ liệu có mật độ thay đổi, hình dạng không cầu hoặc các đặc trưng có thang đo khác nhau. Có thể cần các bước tiền xử lý như chuẩn hóa hoặc tiêu chuẩn hóa để đảm bảo mọi đặc trưng đóng góp như nhau vào việc tính khoảng cách.

<details>
<summary>Ví dụ -- Phân cụm các sự kiện mạng
</summary>
Dưới đây, chúng ta mô phỏng dữ liệu lưu lượng mạng và dùng K-Means để phân cụm dữ liệu. Giả sử chúng ta có các sự kiện với những đặc trưng như thời lượng kết nối và số byte. Chúng ta tạo 3 cụm lưu lượng “bình thường” và 1 cụm nhỏ biểu thị một kiểu tấn công. Sau đó, chúng ta chạy K-Means để xem thuật toán có tách riêng được các cụm này hay không.

```python
import numpy as np
from sklearn.cluster import KMeans

# Simulate synthetic network traffic data (e.g., [duration, bytes]).
# Three normal clusters and one small attack cluster.
rng = np.random.RandomState(42)
normal1 = rng.normal(loc=[50, 500], scale=[10, 100], size=(500, 2))   # Cluster 1
normal2 = rng.normal(loc=[60, 1500], scale=[8, 200], size=(500, 2))   # Cluster 2
normal3 = rng.normal(loc=[70, 3000], scale=[5, 300], size=(500, 2))   # Cluster 3
attack = rng.normal(loc=[200, 800], scale=[5, 50], size=(50, 2))      # Small attack cluster

X = np.vstack([normal1, normal2, normal3, attack])
# Run K-Means clustering into 4 clusters (we expect it to find the 4 groups)
kmeans = KMeans(n_clusters=4, random_state=0, n_init=10)
labels = kmeans.fit_predict(X)

# Analyze resulting clusters
clusters, counts = np.unique(labels, return_counts=True)
print(f"Cluster labels: {clusters}")
print(f"Cluster sizes: {counts}")
print("Cluster centers (duration, bytes):")
for idx, center in enumerate(kmeans.cluster_centers_):
    print(f"  Cluster {idx}: {center}")
```

Trong ví dụ này, K-Means sẽ tìm 4 cụm. Cụm tấn công nhỏ (có thời lượng cao bất thường, khoảng 200) sẽ lý tưởng nhất là tạo thành một cụm riêng do nằm cách xa các cụm bình thường. Chúng ta in kích thước và tâm của các cụm để diễn giải kết quả. Trong tình huống thực tế, có thể gắn nhãn cụm có ít điểm là các bất thường tiềm ẩn hoặc kiểm tra các điểm trong cụm để tìm hoạt động độc hại.
</details>

### Hierarchical Clustering

Phân cụm phân cấp xây dựng một hệ thống phân cấp các cụm bằng cách tiếp cận từ dưới lên (agglomerative) hoặc từ trên xuống (divisive):

1. **Agglomerative (Bottom-Up)**: Bắt đầu với mỗi điểm dữ liệu là một cụm riêng biệt rồi lần lượt gộp các cụm gần nhau nhất cho đến khi chỉ còn một cụm hoặc đạt tiêu chí dừng.
2. **Divisive (Top-Down)**: Bắt đầu với tất cả điểm dữ liệu trong một cụm rồi lần lượt chia các cụm cho đến khi mỗi điểm dữ liệu trở thành một cụm riêng hoặc đạt tiêu chí dừng.

Phân cụm agglomerative cần có định nghĩa về khoảng cách giữa các cụm và tiêu chí liên kết để quyết định nên gộp những cụm nào. Các phương pháp liên kết phổ biến gồm single linkage (khoảng cách giữa các điểm gần nhất của hai cụm), complete linkage (khoảng cách giữa các điểm xa nhất), average linkage, v.v.; metric khoảng cách thường dùng là Euclidean. Việc chọn phương pháp liên kết ảnh hưởng đến hình dạng của các cụm được tạo ra. Không cần xác định trước số lượng cụm K; bạn có thể “cắt” dendrogram ở một mức đã chọn để thu được số cụm mong muốn.

Phân cụm phân cấp tạo ra dendrogram, một cấu trúc dạng cây thể hiện mối quan hệ giữa các cụm ở những mức độ chi tiết khác nhau. Có thể cắt dendrogram ở mức mong muốn để thu được số cụm cụ thể.

> [!TIP]
> *Các trường hợp sử dụng trong an ninh mạng:* Phân cụm phân cấp có thể sắp xếp các sự kiện hoặc thực thể thành một cây để phát hiện các mối quan hệ. Ví dụ, trong phân tích malware, phân cụm agglomerative có thể nhóm các mẫu dựa trên độ tương đồng về hành vi, qua đó làm lộ ra hệ thống phân cấp của các họ và biến thể malware. Trong an ninh mạng, người ta có thể phân cụm các luồng lưu lượng IP rồi dùng dendrogram để xem các nhóm con của lưu lượng (ví dụ: theo giao thức, rồi theo hành vi). Vì không cần chọn trước K, phương pháp này hữu ích khi khám phá dữ liệu mới mà chưa biết số lượng danh mục tấn công.

#### Assumptions and Limitations

Phân cụm phân cấp không giả định một hình dạng cụm cụ thể và có thể phát hiện các cụm lồng nhau. Phương pháp này hữu ích để khám phá hệ thống phân loại hoặc mối quan hệ giữa các nhóm (ví dụ: nhóm malware theo các nhóm nhỏ trong cùng một họ). Phương pháp này có tính xác định (không gặp vấn đề khởi tạo ngẫu nhiên). Một ưu điểm quan trọng là dendrogram, giúp cung cấp thông tin về cấu trúc phân cụm của dữ liệu ở mọi mức độ — các nhà phân tích an ninh có thể chọn ngưỡng cắt thích hợp để xác định các cụm có ý nghĩa. Tuy nhiên, phương pháp này tốn nhiều tài nguyên tính toán (thường có độ phức tạp thời gian $O(n^2)$ hoặc cao hơn với các cách triển khai đơn giản) và không khả thi với các tập dữ liệu rất lớn. Đây cũng là một quy trình tham lam — khi đã thực hiện thao tác gộp hoặc chia, không thể hoàn tác, nên có thể dẫn đến các cụm chưa tối ưu nếu mắc sai lầm ở bước đầu. Các điểm ngoại lệ cũng có thể ảnh hưởng đến một số chiến lược liên kết (single-link có thể gây ra hiệu ứng “chaining”, trong đó các cụm được nối với nhau thông qua các điểm ngoại lệ).

<details>
<summary>Example -- Agglomerative Clustering of Events
</summary>

Chúng ta sẽ dùng lại dữ liệu tổng hợp từ ví dụ K-Means (3 cụm bình thường + 1 cụm tấn công) và áp dụng phân cụm agglomerative. Sau đó, chúng ta minh họa cách tạo dendrogram và nhãn cụm.

```python
from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import linkage, dendrogram

# Perform agglomerative clustering (bottom-up) on the data
agg = AgglomerativeClustering(n_clusters=None, distance_threshold=0, linkage='ward')
# distance_threshold=0 gives the full tree without cutting (we can cut manually)
agg.fit(X)

print(f"Number of merge steps: {agg.n_clusters_ - 1}")  # should equal number of points - 1
# Create a dendrogram using SciPy for visualization (optional)
Z = linkage(X, method='ward')
# Normally, you would plot the dendrogram. Here we'll just compute cluster labels for a chosen cut:
clusters_3 = AgglomerativeClustering(n_clusters=3, linkage='ward').fit_predict(X)
print(f"Labels with 3 clusters: {np.unique(clusters_3)}")
print(f"Cluster sizes for 3 clusters: {np.bincount(clusters_3)}")
```
</details>

### DBSCAN (Phân cụm ứng dụng dựa trên mật độ có nhiễu)

DBSCAN là thuật toán phân cụm dựa trên mật độ, nhóm các điểm nằm gần nhau thành cụm và đánh dấu các điểm trong vùng có mật độ thấp là điểm ngoại lai. Thuật toán này đặc biệt hữu ích với các tập dữ liệu có mật độ thay đổi và hình dạng không phải hình cầu.

DBSCAN hoạt động bằng cách xác định hai tham số:
- **Epsilon (ε)**: Khoảng cách tối đa giữa hai điểm để chúng được xem là thuộc cùng một cụm.
- **MinPts**: Số điểm tối thiểu cần có để hình thành một vùng dày đặc (điểm lõi).

DBSCAN xác định các điểm lõi, điểm biên và điểm nhiễu:
- **Điểm lõi**: Một điểm có ít nhất MinPts điểm lân cận trong khoảng cách ε.
- **Điểm biên**: Một điểm nằm trong khoảng cách ε của một điểm lõi nhưng có ít hơn MinPts điểm lân cận.
- **Điểm nhiễu**: Một điểm không phải điểm lõi cũng không phải điểm biên.

Quá trình phân cụm bắt đầu bằng việc chọn một điểm lõi chưa được duyệt, đánh dấu nó là cụm mới, sau đó đệ quy thêm tất cả các điểm có thể tiếp cận theo mật độ từ điểm đó (các điểm lõi và điểm lân cận của chúng, v.v.). Các điểm biên được thêm vào cụm của một điểm lõi gần đó. Sau khi mở rộng đến tất cả các điểm có thể tiếp cận, DBSCAN chuyển sang một điểm lõi chưa được duyệt khác để bắt đầu cụm mới. Các điểm không được điểm lõi nào tiếp cận vẫn được gán nhãn là nhiễu.

> [!TIP]
> *Trường hợp sử dụng trong an ninh mạng:* DBSCAN hữu ích cho việc phát hiện bất thường trong lưu lượng mạng. Ví dụ: hoạt động bình thường của người dùng có thể tạo thành một hoặc nhiều cụm dày đặc trong không gian đặc trưng, trong khi các hành vi tấn công mới xuất hiện dưới dạng các điểm rải rác mà DBSCAN sẽ gán nhãn là nhiễu (điểm ngoại lai). Thuật toán này đã được dùng để phân cụm các bản ghi luồng mạng, qua đó có thể phát hiện các đợt quét cổng hoặc lưu lượng từ chối dịch vụ dưới dạng các vùng điểm thưa thớt. Một ứng dụng khác là phân nhóm các biến thể malware: nếu hầu hết mẫu được gom cụm theo họ nhưng một số mẫu không phù hợp với nhóm nào, những mẫu đó có thể là malware zero-day. Khả năng đánh dấu nhiễu giúp các nhóm bảo mật tập trung điều tra những điểm ngoại lai đó.

#### Giả định và hạn chế

**Giả định và điểm mạnh:** DBSCAN không giả định các cụm có dạng hình cầu – thuật toán có thể tìm các cụm có hình dạng bất kỳ (kể cả dạng chuỗi hoặc các cụm liền kề). Thuật toán tự xác định số lượng cụm dựa trên mật độ dữ liệu và có thể xác định hiệu quả các điểm ngoại lai dưới dạng nhiễu. Điều này khiến DBSCAN mạnh mẽ khi xử lý dữ liệu thực tế có hình dạng bất quy tắc và có nhiễu. Thuật toán có khả năng chống chịu tốt với điểm ngoại lai (không giống K-Means, vốn buộc các điểm này vào cụm). DBSCAN hoạt động tốt khi các cụm có mật độ tương đối đồng đều.

**Hạn chế**: Hiệu suất của DBSCAN phụ thuộc vào việc chọn giá trị ε và MinPts phù hợp. Thuật toán có thể gặp khó khăn với dữ liệu có mật độ thay đổi – một giá trị ε duy nhất không thể phù hợp cho cả cụm dày đặc lẫn thưa thớt. Nếu ε quá nhỏ, thuật toán sẽ gán nhãn hầu hết các điểm là nhiễu; nếu quá lớn, các cụm có thể bị gộp sai. Ngoài ra, DBSCAN có thể kém hiệu quả trên các tập dữ liệu rất lớn (cách triển khai đơn giản có độ phức tạp $O(n^2)$, dù lập chỉ mục không gian có thể giúp cải thiện). Trong không gian đặc trưng nhiều chiều, khái niệm “khoảng cách trong phạm vi ε” có thể trở nên kém ý nghĩa hơn (lời nguyền số chiều), và DBSCAN có thể cần tinh chỉnh tham số cẩn thận hoặc không tìm được các cụm trực quan. Dù vậy, các phần mở rộng như HDBSCAN giải quyết được một số vấn đề (chẳng hạn như mật độ thay đổi).

<details>
<summary>Ví dụ -- Phân cụm có nhiễu
</summary>

```python
from sklearn.cluster import DBSCAN

# Generate synthetic data: 2 normal clusters and 5 outlier points
cluster1 = rng.normal(loc=[100, 1000], scale=[5, 100], size=(100, 2))
cluster2 = rng.normal(loc=[120, 2000], scale=[5, 100], size=(100, 2))
outliers = rng.uniform(low=[50, 50], high=[180, 3000], size=(5, 2))  # scattered anomalies
data = np.vstack([cluster1, cluster2, outliers])

# Run DBSCAN with chosen eps and MinPts
eps = 15.0   # radius for neighborhood
min_pts = 5  # minimum neighbors to form a dense region
db = DBSCAN(eps=eps, min_samples=min_pts).fit(data)
labels = db.labels_  # cluster labels (-1 for noise)

# Analyze clusters and noise
num_clusters = len(set(labels) - {-1})
num_noise = np.sum(labels == -1)
print(f"DBSCAN found {num_clusters} clusters and {num_noise} noise points")
print("Cluster labels for first 10 points:", labels[:10])
```

Trong đoạn mã này, chúng ta đã tinh chỉnh `eps` và `min_samples` cho phù hợp với quy mô dữ liệu (15.0 theo đơn vị của các đặc trưng, và yêu cầu 5 điểm để tạo thành một cụm). DBSCAN sẽ tìm ra 2 cụm (các cụm lưu lượng bình thường) và đánh dấu 5 outlier được chèn vào là nhiễu. Chúng ta xuất số lượng cụm và điểm nhiễu để kiểm tra kết quả. Trong thực tế, có thể thử nhiều giá trị ε (dùng heuristic biểu đồ k-distance để chọn ε) và MinPts (thường đặt xấp xỉ bằng số chiều dữ liệu + 1 theo quy tắc kinh nghiệm) để tìm kết quả phân cụm ổn định. Khả năng gán nhãn rõ ràng cho nhiễu giúp tách dữ liệu có khả năng là attack để phân tích thêm.

</details>

### Principal Component Analysis (PCA)

PCA là kỹ thuật **giảm chiều dữ liệu**, tìm một tập hợp trục trực giao mới (các thành phần chính) giúp nắm bắt phương sai lớn nhất trong dữ liệu. Nói đơn giản, PCA xoay và chiếu dữ liệu lên một hệ tọa độ mới sao cho thành phần chính thứ nhất (PC1) giải thích phương sai lớn nhất có thể, thành phần chính thứ hai (PC2) giải thích phương sai lớn nhất trong không gian trực giao với PC1, v.v. Về mặt toán học, PCA tính các eigenvector của ma trận hiệp phương sai của dữ liệu — các eigenvector này là hướng của các thành phần chính, còn eigenvalue tương ứng cho biết lượng phương sai được giải thích. PCA thường được dùng để trích xuất đặc trưng, trực quan hóa và giảm nhiễu.

Lưu ý rằng kỹ thuật này hữu ích nếu các chiều của tập dữ liệu có **sự phụ thuộc tuyến tính hoặc tương quan đáng kể**.

PCA hoạt động bằng cách xác định các thành phần chính của dữ liệu, tức là những hướng có phương sai lớn nhất. Các bước thực hiện PCA gồm:
1. **Chuẩn hóa**: Đưa dữ liệu về trung tâm bằng cách trừ đi giá trị trung bình và scale dữ liệu về phương sai đơn vị.
2. **Ma trận hiệp phương sai**: Tính ma trận hiệp phương sai của dữ liệu đã chuẩn hóa để hiểu mối quan hệ giữa các đặc trưng.
3. **Phân rã eigenvalue**: Thực hiện phân rã eigenvalue trên ma trận hiệp phương sai để thu được eigenvalue và eigenvector.
4. **Chọn thành phần chính**: Sắp xếp eigenvalue theo thứ tự giảm dần và chọn K eigenvector đầu tiên tương ứng với các eigenvalue lớn nhất. Các eigenvector này tạo thành không gian đặc trưng mới.
5. **Biến đổi dữ liệu**: Chiếu dữ liệu gốc lên không gian đặc trưng mới bằng các thành phần chính đã chọn.
PCA được sử dụng rộng rãi để trực quan hóa dữ liệu, giảm nhiễu và làm bước tiền xử lý cho các thuật toán machine learning khác. Kỹ thuật này giúp giảm số chiều dữ liệu trong khi vẫn giữ lại cấu trúc thiết yếu của dữ liệu.

#### Eigenvalue và Eigenvector

Eigenvalue là một đại lượng vô hướng cho biết lượng phương sai được nắm bắt bởi eigenvector tương ứng. Eigenvector biểu thị một hướng trong không gian đặc trưng mà theo đó dữ liệu biến thiên nhiều nhất.

Giả sử A là một ma trận vuông, còn v là một vector khác không sao cho: `A * v = λ * v`
trong đó:
- A là ma trận vuông như [ [1, 2], [2, 1]] (ví dụ: ma trận hiệp phương sai)
- v là một eigenvector (ví dụ: [1, 1])

Khi đó, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, tức là eigenvalue λ nhân với eigenvector v, nên eigenvalue λ = 3.

#### Eigenvalue và Eigenvector trong PCA

Hãy giải thích bằng một ví dụ. Giả sử bạn có một tập dữ liệu gồm nhiều ảnh khuôn mặt thang độ xám có kích thước 100x100 pixel. Mỗi pixel có thể được xem là một đặc trưng, vì vậy mỗi ảnh có 10,000 đặc trưng (hoặc một vector gồm 10000 thành phần). Nếu muốn giảm số chiều của tập dữ liệu này bằng PCA, bạn sẽ thực hiện các bước sau:

1. **Chuẩn hóa**: Đưa dữ liệu về trung tâm bằng cách trừ giá trị trung bình của từng đặc trưng (pixel) khỏi tập dữ liệu.
2. **Ma trận hiệp phương sai**: Tính ma trận hiệp phương sai của dữ liệu đã chuẩn hóa; ma trận này nắm bắt mức độ các đặc trưng (pixel) biến thiên cùng nhau.
  - Lưu ý rằng hiệp phương sai giữa hai biến (trong trường hợp này là các pixel) cho biết chúng thay đổi cùng nhau đến mức nào. Vì vậy, mục tiêu ở đây là tìm những pixel có xu hướng cùng tăng hoặc cùng giảm theo mối quan hệ tuyến tính.
  - Ví dụ, nếu pixel 1 và pixel 2 có xu hướng cùng tăng thì hiệp phương sai giữa chúng sẽ dương.
  - Ma trận hiệp phương sai sẽ có kích thước 10,000x10,000; mỗi phần tử biểu thị hiệp phương sai giữa hai pixel.
3. **Giải phương trình eigenvalue**: Phương trình eigenvalue cần giải là `C * v = λ * v`, trong đó C là ma trận hiệp phương sai, v là eigenvector và λ là eigenvalue. Có thể giải bằng các phương pháp như:
  - **Phân rã eigenvalue**: Thực hiện phân rã eigenvalue trên ma trận hiệp phương sai để thu được eigenvalue và eigenvector.
  - **Singular Value Decomposition (SVD)**: Ngoài ra, có thể dùng SVD để phân rã ma trận dữ liệu thành các singular value và vector; kết quả này cũng có thể tạo ra các thành phần chính.
4. **Chọn thành phần chính**: Sắp xếp eigenvalue theo thứ tự giảm dần và chọn K eigenvector đầu tiên tương ứng với các eigenvalue lớn nhất. Những eigenvector này biểu thị các hướng có phương sai lớn nhất trong dữ liệu.

> [!TIP]
> *Các trường hợp sử dụng trong an ninh mạng:* Một ứng dụng phổ biến của PCA trong bảo mật là giảm số đặc trưng để phát hiện bất thường. Ví dụ, hệ thống phát hiện xâm nhập có hơn 40 chỉ số mạng (như các đặc trưng NSL-KDD) có thể dùng PCA để giảm xuống còn một số ít thành phần, tóm tắt dữ liệu để trực quan hóa hoặc đưa vào các thuật toán clustering. Chuyên viên phân tích có thể vẽ lưu lượng mạng trong không gian của hai thành phần chính đầu tiên để xem attack có tách biệt với lưu lượng bình thường hay không. PCA cũng có thể giúp loại bỏ các đặc trưng dư thừa (chẳng hạn như số byte gửi và số byte nhận nếu chúng có tương quan), giúp các thuật toán phát hiện mạnh mẽ và nhanh hơn.

#### Các giả định và hạn chế

PCA giả định rằng **các trục phương sai chính có ý nghĩa** — đây là phương pháp tuyến tính nên chỉ nắm bắt các tương quan tuyến tính trong dữ liệu. Đây là phương pháp unsupervised vì chỉ sử dụng hiệp phương sai của các đặc trưng. Ưu điểm của PCA gồm giảm nhiễu (các thành phần có phương sai nhỏ thường tương ứng với nhiễu) và loại bỏ tương quan giữa các đặc trưng. PCA có hiệu quả tính toán với số chiều tương đối cao và thường là bước tiền xử lý hữu ích cho các thuật toán khác (để giảm thiểu lời nguyền số chiều). Một hạn chế là PCA chỉ xử lý được các mối quan hệ tuyến tính — phương pháp này không nắm bắt được cấu trúc phi tuyến phức tạp (trong khi autoencoder hoặc t-SNE có thể làm được). Ngoài ra, các thành phần PCA có thể khó diễn giải theo các đặc trưng ban đầu (vì chúng là tổ hợp của các đặc trưng gốc). Trong an ninh mạng, cần thận trọng: attack chỉ gây ra thay đổi nhỏ ở một đặc trưng có phương sai thấp có thể không xuất hiện trong các PC hàng đầu (vì PCA ưu tiên phương sai, chứ không nhất thiết là mức độ “đáng quan tâm”).

<details>
<summary>Ví dụ -- Giảm số chiều của dữ liệu mạng
</summary>

Giả sử chúng ta có log kết nối mạng với nhiều đặc trưng (ví dụ: thời lượng, số byte, số lượng). Chúng ta sẽ tạo một tập dữ liệu tổng hợp 4 chiều (trong đó một số đặc trưng có tương quan với nhau) và dùng PCA để giảm xuống còn 2 chiều nhằm trực quan hóa hoặc phân tích thêm.

```python
from sklearn.decomposition import PCA

# Create synthetic 4D data (3 clusters similar to before, but add correlated features)
# Base features: duration, bytes (as before)
base_data = np.vstack([normal1, normal2, normal3])  # 1500 points from earlier normal clusters
# Add two more features correlated with existing ones, e.g. packets = bytes/50 + noise, errors = duration/10 + noise
packets = base_data[:, 1] / 50 + rng.normal(scale=0.5, size=len(base_data))
errors = base_data[:, 0] / 10 + rng.normal(scale=0.5, size=len(base_data))
data_4d = np.column_stack([base_data[:, 0], base_data[:, 1], packets, errors])

# Apply PCA to reduce 4D data to 2D
pca = PCA(n_components=2)
data_2d = pca.fit_transform(data_4d)
print("Explained variance ratio of 2 components:", pca.explained_variance_ratio_)
print("Original shape:", data_4d.shape, "Reduced shape:", data_2d.shape)
# We can examine a few transformed points
print("First 5 data points in PCA space:\n", data_2d[:5])
```

Ở đây, chúng ta lấy các cụm lưu lượng bình thường trước đó và mở rộng mỗi điểm dữ liệu bằng hai đặc trưng bổ sung (packets và errors) có tương quan với bytes và duration. Sau đó, PCA được dùng để nén 4 đặc trưng thành 2 thành phần chính. Chúng ta in tỷ lệ phương sai được giải thích, qua đó có thể thấy rằng, chẳng hạn, >95% phương sai được 2 thành phần nắm bắt (nghĩa là mất rất ít thông tin). Kết quả cũng cho thấy hình dạng dữ liệu giảm từ (1500, 4) xuống (1500, 2). Một vài điểm đầu tiên trong không gian PCA được đưa ra làm ví dụ. Trong thực tế, ta có thể vẽ data_2d để kiểm tra trực quan xem các cụm có thể phân biệt được hay không. Nếu có bất thường, có thể thấy nó dưới dạng một điểm nằm tách xa cụm chính trong không gian PCA. Vì vậy, PCA giúp cô đọng dữ liệu phức tạp thành dạng dễ quản lý để con người diễn giải hoặc dùng làm đầu vào cho các thuật toán khác.

</details>


### Gaussian Mixture Models (GMM)

Gaussian Mixture Model giả định rằng dữ liệu được tạo ra từ hỗn hợp gồm **một số phân phối Gaussian (normal) với các tham số chưa biết**. Về bản chất, đây là một mô hình phân cụm xác suất: mô hình cố gắng gán mềm mỗi điểm vào một trong K thành phần Gaussian. Mỗi thành phần Gaussian k có một vector trung bình (μ_k), ma trận hiệp phương sai (Σ_k) và trọng số hỗn hợp (π_k), biểu thị mức độ phổ biến của cụm đó. Khác với K-Means, vốn thực hiện gán “cứng”, GMM cung cấp cho mỗi điểm xác suất thuộc về từng cụm.

Việc khớp GMM thường được thực hiện bằng thuật toán Expectation-Maximization (EM):

- **Khởi tạo**: Bắt đầu bằng các giá trị ước lượng ban đầu cho trung bình, hiệp phương sai và hệ số hỗn hợp (hoặc dùng kết quả K-Means làm điểm khởi đầu).

- **Bước E (Expectation)**: Với các tham số hiện tại, tính trách nhiệm của mỗi cụm đối với từng điểm: về cơ bản là `r_nk = P(z_k | x_n)`, trong đó z_k là biến tiềm ẩn cho biết điểm x_n thuộc cụm nào. Việc này được thực hiện bằng định lý Bayes: tính xác suất hậu nghiệm để mỗi điểm thuộc về từng cụm dựa trên các tham số hiện tại. Trách nhiệm được tính như sau:
  ```math
  r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
  ```
  trong đó:
  - \( \pi_k \) là hệ số trộn của cụm k (xác suất tiên nghiệm của cụm k),
  - \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) là hàm mật độ xác suất Gaussian của điểm \( x_n \) với trung bình \( \mu_k \) và hiệp phương sai \( \Sigma_k \).

- **M-step (Tối đa hóa)**: Cập nhật các tham số bằng cách sử dụng các giá trị responsibility được tính ở E-step:
  - Cập nhật từng trung bình μ_k thành trung bình có trọng số của các điểm, trong đó trọng số là các giá trị responsibility.
  - Cập nhật từng hiệp phương sai Σ_k thành hiệp phương sai có trọng số của các điểm được gán cho cụm k.
  - Cập nhật các hệ số trộn π_k thành giá trị responsibility trung bình của cụm k.

- **Lặp lại** các bước E và M cho đến khi hội tụ (các tham số ổn định hoặc mức cải thiện likelihood thấp hơn một ngưỡng).

Kết quả là một tập hợp các phân phối Gaussian cùng mô hình hóa phân phối tổng thể của dữ liệu. Ta có thể dùng GMM đã khớp để phân cụm bằng cách gán mỗi điểm cho Gaussian có xác suất cao nhất, hoặc giữ lại các xác suất để biểu thị mức độ không chắc chắn. Ta cũng có thể đánh giá likelihood của các điểm mới để xem chúng có phù hợp với mô hình hay không (hữu ích cho việc phát hiện bất thường).

> [!TIP]
> *Các trường hợp sử dụng trong an ninh mạng:* GMM có thể được dùng để phát hiện bất thường bằng cách mô hình hóa phân phối của dữ liệu bình thường: mọi điểm có xác suất rất thấp theo mô hình hỗn hợp đã học sẽ bị gắn cờ là bất thường. Ví dụ, bạn có thể huấn luyện GMM trên các đặc trưng của lưu lượng mạng hợp lệ; một kết nối tấn công không giống bất kỳ cụm nào đã học sẽ có likelihood thấp. GMM cũng được dùng để phân cụm các hoạt động khi các cụm có thể có hình dạng khác nhau – ví dụ, nhóm người dùng theo hồ sơ hành vi, trong đó các đặc trưng của mỗi hồ sơ có thể gần với phân phối Gaussian nhưng có cấu trúc phương sai riêng. Một tình huống khác: trong phát hiện phishing, các đặc trưng của email hợp lệ có thể tạo thành một cụm Gaussian, phishing đã biết tạo thành một cụm khác, còn các chiến dịch phishing mới có thể xuất hiện như một Gaussian riêng hoặc dưới dạng các điểm có likelihood thấp so với mô hình hỗn hợp hiện có.

#### Giả định và hạn chế

GMM là phiên bản tổng quát hóa của K-Means có tính đến hiệp phương sai, do đó các cụm có thể có dạng ellipsoid (không chỉ hình cầu). Nếu hiệp phương sai đầy đủ, thuật toán có thể xử lý các cụm có kích thước và hình dạng khác nhau. Phân cụm mềm là một lợi thế khi ranh giới giữa các cụm không rõ ràng – ví dụ, trong an ninh mạng, một sự kiện có thể mang đặc điểm của nhiều kiểu tấn công; GMM có thể biểu thị sự không chắc chắn đó bằng xác suất. GMM cũng cung cấp khả năng ước lượng mật độ xác suất của dữ liệu, hữu ích cho việc phát hiện ngoại lệ (các điểm có likelihood thấp theo tất cả thành phần của mô hình hỗn hợp).

Mặt hạn chế là GMM yêu cầu chỉ định số lượng thành phần K (dù có thể dùng các tiêu chí như BIC/AIC để chọn số lượng này). EM đôi khi hội tụ chậm hoặc hội tụ đến một cực trị cục bộ, vì vậy việc khởi tạo rất quan trọng (thường chạy EM nhiều lần). Nếu dữ liệu thực tế không tuân theo mô hình hỗn hợp Gaussian, mô hình có thể khớp kém. Ngoài ra, có nguy cơ một Gaussian co lại để chỉ bao phủ một ngoại lệ (dù có thể giảm thiểu điều này bằng regularization hoặc giới hạn hiệp phương sai tối thiểu).


<details>
<summary>Ví dụ -- Phân cụm mềm & Điểm số bất thường
</summary>

```python
from sklearn.mixture import GaussianMixture

# Fit a GMM with 3 components to the normal traffic data
gmm = GaussianMixture(n_components=3, covariance_type='full', random_state=0)
gmm.fit(base_data)  # using the 1500 normal data points from PCA example

# Print the learned Gaussian parameters
print("GMM means:\n", gmm.means_)
print("GMM covariance matrices:\n", gmm.covariances_)

# Take a sample attack-like point and evaluate it
sample_attack = np.array([[200, 800]])  # an outlier similar to earlier attack cluster
probs = gmm.predict_proba(sample_attack)
log_likelihood = gmm.score_samples(sample_attack)
print("Cluster membership probabilities for sample attack:", probs)
print("Log-likelihood of sample attack under GMM:", log_likelihood)
```

Trong đoạn mã này, chúng ta huấn luyện một GMM với 3 Gaussian trên lưu lượng bình thường (giả sử chúng ta biết 3 hồ sơ lưu lượng hợp lệ). Các giá trị trung bình và hiệp phương sai được in ra mô tả những cụm này (chẳng hạn, một giá trị trung bình có thể xấp xỉ [50,500], tương ứng với tâm của một cụm, v.v.). Sau đó, chúng ta kiểm tra một kết nối đáng ngờ [duration=200, bytes=800]. predict_proba cung cấp xác suất điểm này thuộc về mỗi cụm trong số 3 cụm – chúng ta kỳ vọng các xác suất này rất thấp hoặc lệch nhiều, vì [200,800] nằm xa các cụm bình thường. Giá trị score_samples (log-likelihood) tổng thể được in ra; giá trị rất thấp cho biết điểm này không phù hợp với mô hình, từ đó bị đánh dấu là bất thường. Trong thực tế, có thể đặt ngưỡng cho log-likelihood (hoặc xác suất lớn nhất) để quyết định liệu một điểm có đủ ít khả năng xảy ra để bị xem là độc hại hay không. Vì vậy, GMM cung cấp một phương pháp có cơ sở để phát hiện bất thường, đồng thời tạo ra các cụm mềm có tính đến độ không chắc chắn.
</details>

### Isolation Forest

**Isolation Forest** là một thuật toán phát hiện bất thường dạng ensemble, dựa trên ý tưởng cô lập các điểm một cách ngẫu nhiên. Nguyên lý là các điểm bất thường ít và khác biệt, nên dễ cô lập hơn các điểm bình thường. Isolation Forest tạo nhiều cây cô lập nhị phân (cây quyết định ngẫu nhiên) để phân vùng dữ liệu một cách ngẫu nhiên. Tại mỗi nút trong cây, một đặc trưng được chọn ngẫu nhiên và một giá trị phân tách ngẫu nhiên được chọn trong khoảng từ min đến max của đặc trưng đó trong dữ liệu tại nút. Phép phân tách này chia dữ liệu thành hai nhánh. Cây được phát triển cho đến khi mỗi điểm được cô lập trong một lá riêng hoặc đạt đến chiều cao cây tối đa.

Việc phát hiện bất thường được thực hiện bằng cách quan sát độ dài đường đi của từng điểm trong các cây ngẫu nhiên này – số lần phân tách cần thiết để cô lập điểm đó. Theo trực giác, các điểm bất thường (outlier) thường được cô lập nhanh hơn vì một phép phân tách ngẫu nhiên có khả năng tách một outlier (nằm trong vùng thưa dữ liệu) cao hơn so với một điểm bình thường trong cụm dày đặc. Isolation Forest tính điểm bất thường dựa trên độ dài đường đi trung bình qua tất cả các cây: đường đi trung bình càng ngắn → càng bất thường. Điểm số thường được chuẩn hóa về [0,1], trong đó 1 có nghĩa là rất có khả năng là bất thường.

> [!TIP]
> *Trường hợp sử dụng trong an ninh mạng:* Isolation Forest đã được sử dụng hiệu quả trong phát hiện xâm nhập và phát hiện gian lận. Ví dụ, huấn luyện Isolation Forest trên nhật ký lưu lượng mạng chủ yếu chứa hành vi bình thường; rừng sẽ tạo ra các đường đi ngắn cho lưu lượng bất thường (chẳng hạn như IP sử dụng một cổng chưa từng thấy hoặc có kiểu kích thước gói bất thường), đánh dấu chúng để kiểm tra. Vì không cần các cuộc tấn công đã được gán nhãn, thuật toán này phù hợp để phát hiện các kiểu tấn công chưa biết. Nó cũng có thể được triển khai trên dữ liệu đăng nhập của người dùng để phát hiện chiếm đoạt tài khoản (thời gian hoặc vị trí đăng nhập bất thường sẽ nhanh chóng bị cô lập). Trong một trường hợp sử dụng, Isolation Forest có thể bảo vệ doanh nghiệp bằng cách giám sát các chỉ số hệ thống và phát cảnh báo khi một tổ hợp chỉ số (CPU, mạng, thay đổi tệp) khác biệt rõ rệt (đường đi cô lập ngắn) so với các mẫu lịch sử.

#### Các giả định và hạn chế

**Ưu điểm**: Isolation Forest không đòi hỏi giả định về phân phối; thuật toán trực tiếp nhắm đến việc cô lập. Nó hoạt động hiệu quả trên dữ liệu nhiều chiều và tập dữ liệu lớn (độ phức tạp tuyến tính $O(n\log n)$ khi xây dựng rừng), vì mỗi cây cô lập các điểm chỉ bằng một tập con đặc trưng và các phép phân tách. Thuật toán thường xử lý tốt các đặc trưng số và có thể nhanh hơn các phương pháp dựa trên khoảng cách, vốn có thể có độ phức tạp $O(n^2)$. Nó cũng tự động cung cấp điểm bất thường, cho phép bạn đặt ngưỡng cảnh báo (hoặc dùng tham số contamination để tự động xác định ngưỡng dựa trên tỷ lệ bất thường dự kiến).

**Hạn chế**: Do có tính ngẫu nhiên, kết quả có thể thay đổi đôi chút giữa các lần chạy (dù sự khác biệt này không đáng kể nếu có đủ số cây). Nếu dữ liệu có nhiều đặc trưng không liên quan hoặc các điểm bất thường không khác biệt rõ rệt ở bất kỳ đặc trưng nào, việc cô lập có thể không hiệu quả (các phép phân tách ngẫu nhiên có thể vô tình cô lập các điểm bình thường – tuy nhiên, việc lấy trung bình qua nhiều cây giúp giảm thiểu điều này). Ngoài ra, Isolation Forest thường giả định các điểm bất thường chỉ chiếm thiểu số nhỏ (điều này thường đúng trong các tình huống an ninh mạng).

<details>
<summary>Ví dụ -- Phát hiện các điểm ngoại lệ trong nhật ký mạng
</summary>

Chúng ta sẽ dùng lại tập dữ liệu kiểm thử trước đó (có chứa các điểm bình thường và một số điểm tấn công) rồi chạy Isolation Forest để xem liệu thuật toán có thể phân biệt các cuộc tấn công hay không. Chúng ta sẽ giả định khoảng 15% dữ liệu là bất thường (để minh họa).

```python
from sklearn.ensemble import IsolationForest

# Combine normal and attack test data from autoencoder example
X_test_if = test_data  # (120 x 2 array with 100 normal and 20 attack points)
# Train Isolation Forest (unsupervised) on the test set itself for demo (in practice train on known normal)
iso_forest = IsolationForest(n_estimators=100, contamination=0.15, random_state=0)
iso_forest.fit(X_test_if)
# Predict anomalies (-1 for anomaly, 1 for normal)
preds = iso_forest.predict(X_test_if)
anomaly_scores = iso_forest.decision_function(X_test_if)  # the higher, the more normal
print("Isolation Forest predicted labels (first 20):", preds[:20])
print("Number of anomalies detected:", np.sum(preds == -1))
print("Example anomaly scores (lower means more anomalous):", anomaly_scores[:5])
```

Trong đoạn code này, chúng ta khởi tạo `IsolationForest` với 100 cây và đặt `contamination=0.15` (nghĩa là dự kiến khoảng 15% là anomaly; model sẽ đặt ngưỡng điểm sao cho khoảng 15% điểm bị đánh dấu). Chúng ta fit model trên `X_test_if`, chứa cả điểm bình thường lẫn điểm tấn công (lưu ý: thông thường bạn sẽ fit model trên dữ liệu huấn luyện rồi dùng `predict` trên dữ liệu mới, nhưng ở đây để minh họa, chúng ta fit và predict trên cùng một tập nhằm quan sát trực tiếp kết quả).

Kết quả hiển thị các nhãn dự đoán cho 20 điểm đầu tiên (trong đó -1 biểu thị anomaly). Chúng ta cũng in tổng số anomaly được phát hiện và một số điểm anomaly mẫu. Dự kiến khoảng 18 trong số 120 điểm sẽ được gán nhãn -1 (vì contamination được đặt là 15%). Nếu 20 mẫu tấn công thực sự là những điểm khác biệt nhất, phần lớn chúng sẽ xuất hiện trong các dự đoán -1 đó. Điểm anomaly (hàm decision của Isolation Forest) cao hơn đối với các điểm bình thường và thấp hơn (âm hơn) đối với anomaly – chúng ta in một vài giá trị để quan sát mức độ phân tách. Trong thực tế, người ta có thể sắp xếp dữ liệu theo điểm số để xem các điểm ngoại lai nổi bật nhất và điều tra chúng. Vì vậy, Isolation Forest cung cấp một cách hiệu quả để sàng lọc lượng lớn dữ liệu bảo mật chưa gán nhãn và chọn ra những trường hợp bất thường nhất để con người phân tích hoặc tiếp tục kiểm tra tự động.
</details>


### t-SNE (Nhúng hàng xóm ngẫu nhiên phân phối t)

**t-SNE** là kỹ thuật giảm chiều phi tuyến được thiết kế riêng để trực quan hóa dữ liệu nhiều chiều trong không gian 2 hoặc 3 chiều. Kỹ thuật này chuyển đổi mức độ tương đồng giữa các điểm dữ liệu thành các phân phối xác suất chung và cố gắng bảo toàn cấu trúc của các vùng lân cận cục bộ trong phép chiếu xuống không gian chiều thấp. Nói đơn giản hơn, t-SNE sắp xếp các điểm trong (chẳng hạn) không gian 2D sao cho các điểm tương đồng (trong không gian ban đầu) có xác suất cao nằm gần nhau, còn các điểm không tương đồng nằm xa nhau.

Thuật toán có ba giai đoạn chính:

1. **Tính độ liên kết từng cặp trong không gian nhiều chiều:** Với mỗi cặp điểm, t-SNE tính xác suất chọn cặp đó làm hàng xóm (việc này được thực hiện bằng cách đặt một phân phối Gaussian tại mỗi điểm và đo khoảng cách – tham số perplexity ảnh hưởng đến số lượng hàng xóm hữu hiệu được xét đến).
2. **Tính độ liên kết từng cặp trong không gian chiều thấp (ví dụ: 2D):** Ban đầu, các điểm được đặt ngẫu nhiên trong không gian 2D. t-SNE xác định một xác suất tương tự cho khoảng cách trên bản đồ này (sử dụng kernel phân phối t Student, có phần đuôi dày hơn Gaussian để các điểm ở xa có nhiều khoảng trống hơn).
3. **Gradient Descent:** Sau đó, t-SNE liên tục di chuyển các điểm trong không gian 2D để giảm thiểu độ phân kỳ Kullback–Leibler (KL) giữa phân phối độ liên kết trong không gian nhiều chiều và phân phối trong không gian chiều thấp. Nhờ vậy, cách sắp xếp trong không gian 2D phản ánh cấu trúc trong không gian nhiều chiều hết mức có thể – các điểm vốn nằm gần nhau trong không gian ban đầu sẽ hút nhau, còn các điểm ở xa sẽ đẩy nhau, cho đến khi đạt trạng thái cân bằng.

Kết quả thường là biểu đồ phân tán có ý nghĩa trực quan, trong đó các cụm dữ liệu trở nên dễ nhận thấy.

> [!TIP]
> *Ứng dụng trong an ninh mạng:* t-SNE thường được dùng để **trực quan hóa dữ liệu bảo mật nhiều chiều nhằm phục vụ phân tích của con người**. Ví dụ, tại trung tâm điều hành an ninh, các nhà phân tích có thể lấy một tập dữ liệu sự kiện với hàng chục đặc trưng (số cổng, tần suất, số byte, v.v.) và dùng t-SNE để tạo biểu đồ 2D. Các cuộc tấn công có thể tạo thành cụm riêng hoặc tách khỏi dữ liệu bình thường trên biểu đồ này, giúp dễ nhận diện hơn. Phương pháp này đã được áp dụng cho các tập dữ liệu malware để quan sát các nhóm malware family, hoặc cho dữ liệu xâm nhập mạng, nơi các loại tấn công khác nhau tạo thành những cụm riêng biệt, từ đó định hướng điều tra thêm. Về cơ bản, t-SNE giúp nhìn thấy cấu trúc trong dữ liệu mạng mà nếu không thì sẽ rất khó hiểu.

#### Giả định và hạn chế

t-SNE rất hữu ích để khám phá trực quan các mẫu. Phương pháp này có thể phát hiện cụm, cụm con và điểm ngoại lai mà các phương pháp tuyến tính khác (như PCA) có thể bỏ sót. Nó đã được sử dụng trong nghiên cứu an ninh mạng để trực quan hóa dữ liệu phức tạp như hồ sơ hành vi malware hoặc mẫu lưu lượng mạng. Vì bảo toàn cấu trúc cục bộ, phương pháp này phù hợp để thể hiện các nhóm tự nhiên.

Tuy nhiên, t-SNE đòi hỏi nhiều tài nguyên tính toán hơn (xấp xỉ $O(n^2)$), vì vậy có thể cần lấy mẫu với các tập dữ liệu rất lớn. Phương pháp này cũng có các siêu tham số (perplexity, learning rate, số vòng lặp) có thể ảnh hưởng đến kết quả – ví dụ, các giá trị perplexity khác nhau có thể làm lộ ra các cụm ở những quy mô khác nhau. Biểu đồ t-SNE đôi khi có thể bị diễn giải sai – khoảng cách trên bản đồ không có ý nghĩa trực tiếp trên toàn cục (phương pháp tập trung vào vùng lân cận cục bộ, đôi khi các cụm có thể trông như được tách biệt rõ rệt một cách giả tạo). Ngoài ra, t-SNE chủ yếu dùng để trực quan hóa; phương pháp này không cung cấp cách đơn giản để chiếu các điểm dữ liệu mới mà không tính toán lại, và không được thiết kế để làm bước tiền xử lý cho mô hình dự đoán (UMAP là một lựa chọn thay thế khắc phục một số vấn đề này và có tốc độ nhanh hơn).

<details>
<summary>Ví dụ -- Trực quan hóa các kết nối mạng
</summary>

Chúng ta sẽ dùng t-SNE để giảm một tập dữ liệu nhiều đặc trưng xuống 2D. Để minh họa, hãy lấy dữ liệu 4D trước đó (có 3 cụm lưu lượng bình thường tự nhiên) và thêm một vài điểm anomaly. Sau đó, chúng ta chạy t-SNE và (về mặt khái niệm) trực quan hóa kết quả.

```python
# 1 ─────────────────────────────────────────────────────────────────────
#    Create synthetic 4-D dataset
#      • Three clusters of “normal” traffic (duration, bytes)
#      • Two correlated features: packets & errors
#      • Five outlier points to simulate suspicious traffic
# ──────────────────────────────────────────────────────────────────────
import numpy as np
import matplotlib.pyplot as plt
from sklearn.manifold import TSNE
from sklearn.preprocessing import StandardScaler

rng = np.random.RandomState(42)

# Base (duration, bytes) clusters
normal1 = rng.normal(loc=[50, 500],  scale=[10, 100], size=(500, 2))
normal2 = rng.normal(loc=[60, 1500], scale=[8,  200], size=(500, 2))
normal3 = rng.normal(loc=[70, 3000], scale=[5,  300], size=(500, 2))

base_data = np.vstack([normal1, normal2, normal3])       # (1500, 2)

# Correlated features
packets = base_data[:, 1] / 50 + rng.normal(scale=0.5, size=len(base_data))
errors  = base_data[:, 0] / 10 + rng.normal(scale=0.5, size=len(base_data))

data_4d = np.column_stack([base_data, packets, errors])  # (1500, 4)

# Outlier / attack points
outliers_4d = np.column_stack([
    rng.normal(250, 1, size=5),     # extreme duration
    rng.normal(1000, 1, size=5),    # moderate bytes
    rng.normal(5, 1, size=5),       # very low packets
    rng.normal(25, 1, size=5)       # high errors
])

data_viz = np.vstack([data_4d, outliers_4d])             # (1505, 4)

# 2 ─────────────────────────────────────────────────────────────────────
#    Standardize features (recommended for t-SNE)
# ──────────────────────────────────────────────────────────────────────
scaler = StandardScaler()
data_scaled = scaler.fit_transform(data_viz)

# 3 ─────────────────────────────────────────────────────────────────────
#    Run t-SNE to project 4-D → 2-D
# ──────────────────────────────────────────────────────────────────────
tsne = TSNE(
    n_components=2,
    perplexity=30,
    learning_rate='auto',
    init='pca',
    random_state=0
)
data_2d = tsne.fit_transform(data_scaled)
print("t-SNE output shape:", data_2d.shape)  # (1505, 2)

# 4 ─────────────────────────────────────────────────────────────────────
#    Visualize: normal traffic vs. outliers
# ──────────────────────────────────────────────────────────────────────
plt.figure(figsize=(8, 6))
plt.scatter(
    data_2d[:-5, 0], data_2d[:-5, 1],
    label="Normal traffic",
    alpha=0.6,
    s=10
)
plt.scatter(
    data_2d[-5:, 0], data_2d[-5:, 1],
    label="Outliers / attacks",
    alpha=0.9,
    s=40,
    marker="X",
    edgecolor='k'
)

plt.title("t-SNE Projection of Synthetic Network Traffic")
plt.xlabel("t-SNE component 1")
plt.ylabel("t-SNE component 2")
plt.legend()
plt.tight_layout()
plt.show()
```

Ở đây, chúng ta kết hợp dataset chuẩn 4D trước đó với một vài outlier cực đoan (một feature (“duration”) của các outlier được đặt ở mức rất cao, v.v. để mô phỏng một mẫu bất thường). Chúng ta chạy t-SNE với perplexity điển hình là 30. Dữ liệu đầu ra `data_2d` có shape (1505, 2). Trong văn bản này, chúng ta sẽ không vẽ biểu đồ, nhưng nếu có, ta kỳ vọng sẽ thấy khoảng ba cụm chặt chẽ tương ứng với 3 cụm chuẩn và 5 outlier xuất hiện thành các điểm riêng lẻ, nằm cách xa những cụm đó. Trong quy trình làm việc tương tác, ta có thể tô màu các điểm theo nhãn của chúng (bình thường hoặc thuộc cụm nào, so với anomaly) để xác minh cấu trúc này. Ngay cả khi không có nhãn, nhà phân tích có thể nhận thấy 5 điểm đó nằm trong vùng trống trên biểu đồ 2D và đánh dấu chúng. Điều này cho thấy t-SNE có thể hỗ trợ mạnh mẽ cho việc phát hiện anomaly bằng trực quan hóa và kiểm tra cụm trong dữ liệu an ninh mạng, bổ trợ cho các thuật toán tự động ở trên.

</details>


### HDBSCAN (Phân cụm không gian dựa trên mật độ phân cấp với nhiễu)

**HDBSCAN** là phần mở rộng của DBSCAN, loại bỏ nhu cầu chọn một giá trị `eps` toàn cục duy nhất và có khả năng tìm ra các cụm có **mật độ khác nhau** bằng cách xây dựng rồi cô đọng hệ phân cấp các thành phần liên kết theo mật độ. So với DBSCAN cơ bản, thuật toán này thường

* trích xuất các cụm trực quan hơn khi một số cụm dày đặc còn những cụm khác thưa thớt,
* chỉ có một siêu tham số thực sự (`min_cluster_size`) và có giá trị mặc định hợp lý,
* cung cấp cho mỗi điểm một *xác suất* thuộc cụm và **điểm outlier** (`outlier_scores_`), rất hữu ích cho các dashboard threat-hunting.<sup>[[1]](#references)</sup>

> [!TIP]
> *Các trường hợp sử dụng trong an ninh mạng:* HDBSCAN rất phổ biến trong các pipeline threat-hunting hiện đại – bạn thường sẽ thấy nó trong các playbook hunting dựa trên notebook đi kèm với các bộ XDR thương mại. Một cách áp dụng thực tế là phân cụm lưu lượng beaconing HTTP trong quá trình IR: user-agent, khoảng thời gian và độ dài URI thường tạo thành một số nhóm chặt chẽ gồm các chương trình cập nhật phần mềm hợp pháp, trong khi beacon C2 vẫn nằm trong các cụm mật độ thấp rất nhỏ hoặc bị xem là nhiễu thuần túy.

<details>
<summary>Ví dụ – Tìm các kênh C2 beaconing</summary>

```python
import pandas as pd
from hdbscan import HDBSCAN
from sklearn.preprocessing import StandardScaler

# df has features extracted from proxy logs
features = [
    "avg_interval",      # seconds between requests
    "uri_length_mean",   # average URI length
    "user_agent_entropy" # Shannon entropy of UA string
]
X = StandardScaler().fit_transform(df[features])

hdb = HDBSCAN(min_cluster_size=15,  # at least 15 similar beacons to be a group
              metric="euclidean",
              prediction_data=True)
labels = hdb.fit_predict(X)

df["cluster"] = labels
# Anything with label == -1 is noise → inspect as potential C2
suspects = df[df["cluster"] == -1]
print("Suspect beacon count:", len(suspects))
```

</details>

---

### Các cân nhắc về độ bền vững và bảo mật – Tấn công đầu độc và đối kháng (2023-2025)

Các nghiên cứu gần đây cho thấy **các mô hình học không giám sát *không* miễn nhiễm trước những kẻ tấn công chủ động**:

* **Đầu độc dữ liệu nhằm vào các bộ phát hiện bất thường.** Chen *et al.* (IEEE S&P 2024) chứng minh rằng chỉ cần thêm 3% lưu lượng được tạo có chủ đích cũng có thể làm dịch chuyển ranh giới quyết định của Isolation Forest và ECOD, khiến các cuộc tấn công thực sự trông như bình thường. Các tác giả đã phát hành PoC mã nguồn mở (`udo-poison`) có thể tự động tổng hợp các điểm đầu độc.<sup>[[2]](#references)</sup>
* **Cài backdoor vào các mô hình phân cụm.** Kỹ thuật *BadCME* (BlackHat EU 2023) cài một mẫu kích hoạt nhỏ; bất cứ khi nào mẫu đó xuất hiện, bộ phát hiện dựa trên K-Means sẽ âm thầm xếp sự kiện vào một cụm “lành tính”.
* **Né tránh DBSCAN/HDBSCAN.** Một bản tiền ấn phẩm học thuật năm 2025 của KU Leuven cho thấy kẻ tấn công có thể tạo các mẫu beaconing cố ý rơi vào những khoảng trống về mật độ, qua đó ẩn mình hiệu quả trong các nhãn *nhiễu*.

Các biện pháp giảm thiểu đang ngày càng được áp dụng:

1. **Làm sạch mô hình / TRIM.** Trước mỗi epoch huấn luyện lại, loại bỏ 1–2% điểm có loss cao nhất (ước lượng hợp lý cực đại đã cắt tỉa) để khiến việc đầu độc khó hơn đáng kể.
2. **Tổ hợp đồng thuận.** Kết hợp một số bộ phát hiện khác nhau (ví dụ: Isolation Forest + GMM + ECOD) và phát cảnh báo nếu *bất kỳ* mô hình nào gắn cờ một điểm. Nghiên cứu cho thấy biện pháp này làm tăng chi phí của kẻ tấn công hơn 10 lần.
3. **Phòng thủ dựa trên khoảng cách cho phân cụm.** Tính toán lại các cụm với `k` seed ngẫu nhiên khác nhau và bỏ qua những điểm liên tục chuyển cụm.

---

### Công cụ mã nguồn mở hiện đại (2024-2025)

* **PyOD 2.x** (phát hành tháng 5 năm 2024) bổ sung các bộ phát hiện *ECOD*, *COPOD* và *AutoFormer* được tăng tốc bằng GPU. Hiện thư viện có lệnh con `benchmark`, cho phép bạn so sánh hơn 30 thuật toán trên tập dữ liệu của mình chỉ bằng **một dòng mã**:
  ```bash
  pyod benchmark --input logs.csv --label attack --n_jobs 8
  ```
* **Anomalib v1.5** (Feb 2025) tập trung vào thị giác nhưng cũng có phần triển khai **PatchCore** tổng quát – hữu ích để phát hiện trang phishing dựa trên ảnh chụp màn hình.
* **scikit-learn 1.5** (Nov 2024) cuối cùng cũng cung cấp `score_samples` cho *HDBSCAN* thông qua wrapper `cluster.HDBSCAN` mới, vì vậy bạn không cần dùng gói contrib bên ngoài khi chạy Python 3.12.

<details>
<summary>Ví dụ PyOD nhanh – ensemble ECOD + Isolation Forest</summary>

```python
from pyod.models import ECOD, IForest
from pyod.utils.data import generate_data, evaluate_print
from pyod.utils.example import visualize

X_train, y_train, X_test, y_test = generate_data(
    n_train=5000, n_test=1000, n_features=16,
    contamination=0.02, random_state=42)

models = [ECOD(), IForest()]

# majority vote – flag if any model thinks it is anomalous
anomaly_scores = sum(m.fit(X_train).decision_function(X_test) for m in models) / len(models)

evaluate_print("Ensemble", y_test, anomaly_scores)
```

</details>

## References

- [1] [HDBSCAN – Phân cụm phân cấp dựa trên mật độ](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* “Tính dễ bị tổn thương của phương pháp phát hiện bất thường không giám sát trước hành vi đầu độc dữ liệu.” *IEEE Symposium on Security and Privacy*, 2024.

{{#include ../banners/hacktricks-training.md}}
