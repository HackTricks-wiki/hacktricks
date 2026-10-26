# Tấn công đối kháng được hướng dẫn bởi khả năng diễn giải cơ chế

{{#include ../banners/hacktricks-training.md}}

## Chồng lấp như một bề mặt tấn công

Một không gian activation thiếu tham số có thể mã hóa nhiều đặc trưng ngữ nghĩa hơn số chiều của nó bằng cách gán các đặc trưng cho những vector không trực giao. Do đó, một đặc trưng được kích hoạt cũng chiếu lên các hướng đặc trưng khác. Quá trình huấn luyện có thể bù trừ cho các tổ hợp xuất hiện trong phân phối dữ liệu, nhưng một tổ hợp bất thường gồm các đặc trưng hợp lệ riêng lẻ có thể cộng dồn theo hướng của một đặc trưng đích không có trong đầu vào.<sup>[[1]](#references)[[2]](#references)</sup>

Với các vector đặc trưng `v_i ∈ R^D`, các giá trị kích hoạt `a_i` và mục tiêu `t`, độ lớn sau đây hữu ích để tìm các tổ hợp tiềm năng:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

Đây chỉ là một heuristic sàng lọc. Một exploit phải giữ nguyên dấu và độ lớn, đồng thời đánh giá decoder thực tế, chẳng hạn `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` trong một tied-weight linear decoder. Các số hạng âm có thể triệt tiêu cuộc tấn công, trong khi bias của decoder, chuẩn vector đặc trưng, ngưỡng kích hoạt và cơ chế ReLU gating có thể khiến điểm cosine tuyệt đối lớn không tạo ra được activation mục tiêu.<sup>[[1]](#references)</sup>

## Quy trình tấn công White-box

Một đánh giá thực tế có thể sử dụng nút thắt của mô hình, sparse autoencoder (SAE) hoặc một từ điển đặc trưng có thể diễn giải khác. Mục tiêu không chỉ là thay đổi lớp đầu ra: mà còn khiến quá trình tái tạo đưa vào một đặc trưng nội bộ đã chọn, vốn chưa hoạt động trước khi nén. Quy trình được đề xuất như sau:<sup>[[1]](#references)</sup>

1. **Khôi phục các hướng đặc trưng:** trích xuất các vector encoder/decoder liên quan, loại bỏ các đặc trưng chết và ánh xạ các hướng đang hoạt động sang khái niệm bằng cách dùng mẫu kích hoạt tối đa hoặc phân tích mạch đặc trưng.
2. **Xếp hạng mức độ can nhiễu:** chuẩn hóa một bản sao của các vector, tính ma trận độ tương đồng cosine, xóa các phần tử trên đường chéo và kiểm tra các đặc trưng lân cận ngoài đường chéo có điểm cao nhất của mục tiêu. Tính lại điểm các ứng viên bằng độ lớn activation thực tế và tích vô hướng thô có dấu.
3. **Đảm bảo đồng kích hoạt:** giữ lại một tập nhỏ các đặc trưng đóng góp dương có thể được kích hoạt trong cùng một layer hoặc residual stream. Ưu tiên các tổ hợp hiếm hoặc không có trong dữ liệu huấn luyện; các tổ hợp tương quan thông thường có khả năng đã được bù trừ trong quá trình huấn luyện.
4. **Tổng hợp đầu vào:** kết hợp các ví dụ trong dataset hoặc các mẫu tối đa hóa activation cho những đặc trưng đóng góp đã chọn. Với bộ phát hiện pixel tuyến tính có giới hạn, đặt pixel ở mức cao nếu trọng số dương và mức thấp nếu trọng số âm, rồi chồng các mẫu thu được lên nhau. Việc giữ cấu trúc theo phân phối dữ liệu và các **khoảng trống âm** một cách thủ công có thể triệt tiêu các đặc trưng không liên quan.
5. **Xác minh cơ chế:** ghi lại activation trước khi nén, các tọa độ đã nén, activation được tái tạo và đầu ra phía sau trong cùng một lượt forward. Một phép thử thành công cho thấy mục tiêu không hoạt động trước khi tái tạo nhưng hoạt động sau đó; đồng thời, thay đổi dự đoán sẽ biến mất khi ablate các đặc trưng đóng góp.

Đoạn triage tối giản sau đây xếp hạng các đặc trưng đóng góp cho một decoder tied-weight có các vector đặc trưng nằm trên **các hàng** (nếu đặc trưng nằm trên các cột thì hãy chuyển vị trước). Dùng trọng số thô để tính điểm có dấu và chỉ dùng trọng số đã chuẩn hóa để xếp hạng cosine.<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

Không nên suy luận về khả năng khai thác chỉ dựa trên cosine similarity. Hãy kiểm thử toàn bộ decoder cùng bias và tính phi tuyến của nó, xác nhận rằng các thành phần đóng góp thực sự có thể đồng thời xuất hiện, và so sánh với các tổ hợp trong phân phối có đặc điểm tương đồng. Các hướng tương tự có thể biểu diễn một mối liên hệ ngữ nghĩa hợp lệ, chứ không phải hiện tượng can thiệp do đóng gói gây ra, có thể khai thác được.<sup>[[1]](#references)</sup>

## Tấn công toy model đã được chứng minh

Bằng chứng khái niệm sử dụng một bộ phân loại MNIST có chủ đích dễ diễn giải, gồm hai nhánh. Một vector đặc trưng ReLU thưa, 128 chiều, được phân loại trực tiếp ở một nhánh và nén vào không gian chồng lấp hai chiều ở nhánh còn lại; cùng một bộ phân loại xử lý cả các đặc trưng ban đầu lẫn các đặc trưng được tái tạo.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

Hai hướng feature gắn với hình dạng giống 3/0 được bao quanh về mặt hình học bởi các hướng class-5. Việc cộng các ảnh kích hoạt tối đa của chúng khiến các feature đóng góp này mạnh nhất trước khi nén, nhưng quá trình tái tạo đã kích hoạt một số feature class-5 và nhánh superposition dự đoán 5. Một đầu vào vẽ tay chỉ sử dụng các giá trị pixel tối thiểu/tối đa cũng tái tạo hiệu ứng này, cho thấy trong thiết lập đồ chơi này, không cần các nhiễu loạn pixel được tối ưu hóa chính xác theo gradient.<sup>[[1]](#references)</sup>

## Sàng lọc hình học trên mô hình lớn hơn

Bài báo cũng khảo sát SAE Gemma Scope `layer 20 / width 65k / average L0 20`. Nhóm tác giả nhân ma trận decoder đã chuẩn hóa theo đơn vị với ma trận chuyển vị của nó, xóa đường chéo, sắp xếp các láng giềng của từng feature, rồi lấy trung bình theo thứ hạng. Độ tương đồng cosine trung bình của láng giềng mạnh nhất là `0.49`, trong khi độ tương đồng của láng giềng thứ 27 là `0.25`; xét về hình học, bốn hướng như vậy có thể khớp với phép chiếu mục tiêu của một đơn vị. Các con số này chỉ giúp xác định các ứng viên—chúng không chứng minh rằng có thể cùng kích hoạt bốn feature phù hợp hoặc mục tiêu vượt ngưỡng decoder của nó.<sup>[[1]](#references)</sup>

## Phạm vi và hạn chế

Đây là kỹ thuật đang ở giai đoạn nghiên cứu **white-box**, không phải một cuộc tấn công đã được chứng minh nhằm vào CNN đang triển khai hoặc LLM tiên tiến. Kỹ thuật này đòi hỏi superposition, các hướng không trực giao hữu ích, khả năng truy cập có thể diễn giải vào các feature bên trong, khả năng kiểm soát việc kích hoạt các feature đóng góp, và việc tập hợp chúng trong cùng một layer trong một lượt truyền xuôi.<sup>[[1]](#references)</sup>

MLP xử lý ảnh giúp việc kết hợp feature đặc biệt trực tiếp. Transformer khó hơn vì attention phải tập hợp các activation feature đã chọn vào cùng một residual stream; bài báo không chỉ ra cách ép buộc điều này với một tổ hợp nằm ngoài phân phối. Do đó, các tuyên bố về việc thao túng hướng hành vi hoặc hướng từ chối, hệ thống thị giác vật lý hay mô hình tiên tiến vẫn chỉ là giả thuyết.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — A Preliminary Investigation Into Interpretable Adversarial Attacks Through Feature Interference in Superposition (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Interpretable Adversarial Attacks in Superposition](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
