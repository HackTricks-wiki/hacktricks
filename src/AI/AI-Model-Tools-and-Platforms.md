# Công cụ và nền tảng mô hình AI

{{#include ../banners/hacktricks-training.md}}

## Chạy và huấn luyện mô hình cục bộ

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers là thư viện mã nguồn mở để tải, huấn luyện và phục vụ các mô hình được huấn luyện trước cho những tác vụ về văn bản, hình ảnh, âm thanh, video và đa phương thức. Việc lưu trữ mô hình và tập dữ liệu được cung cấp riêng thông qua Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain là framework để xây dựng các ứng dụng và agent điều khiển bằng mô hình, với các chức năng tạo prompt, quản lý lịch sử/trạng thái hội thoại, công cụ, truy xuất, tích hợp mô hình, API và cơ sở dữ liệu.<sup>[[2]](#references)</sup>

#### Kiểm tra việc phục hồi đối tượng đã tuần tự hóa của LangChain

Khi ứng dụng chấp nhận đầu vào có cấu trúc từ người dùng hoặc đầu ra của mô hình, hãy kiểm tra xem các từ điển lồng nhau có được giữ nguyên trong `metadata`, `additional_kwargs`, `response_metadata`, lịch sử trò chuyện đã lưu hoặc luồng chạy hay không. LangChain sử dụng các từ điển được gắn thẻ `lc` làm đối tượng đã tuần tự hóa. Trong các vòng chuyển đổi `dumps()`/`dumpd()` → `load()`/`loads()` bị ảnh hưởng, một từ điển do kẻ tấn công kiểm soát có thể được phục hồi thành đối tượng của framework thay vì vẫn là dữ liệu. Việc tải trực tiếp một manifest không đáng tin cậy cũng rất nguy hiểm; đầu vào chuỗi thông thường không bao giờ được phân tích thành từ điển thì không đáp ứng điều kiện tiên quyết này.<sup>[[10]](#references)[[11]](#references)</sup>

Để kiểm tra được ủy quyền, hãy gửi một canary vô hại có cấu trúc như lời gọi constructor **dưới dạng đối tượng JSON lồng nhau**, không phải chuỗi, rồi kiểm tra xem lịch sử hoặc luồng ở bước tiếp theo có chứa đối tượng `AIMessage` thay vì từ điển ban đầu hay không:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Kiểm tra `RunnableWithMessageHistory`, `astream_log()` và `astream_events(version="v1")` khi chúng thực sự được sử dụng. Việc khôi phục đối tượng thành công có thể làm nhiễm độc lịch sử trò chuyện về sau; allowlist rộng hơn có thể khởi tạo các class đáng tin cậy khác có constructor gây tác dụng phụ. Đừng đánh đồng điều này với việc thực thi pickle không hạn chế. Lỗ hổng thoát ban đầu đã được khắc phục trong `langchain-core` 0.3.81/1.2.5, và bản sửa lỗi sau đó cho allowlist rộng cùng dấu đánh dấu bí mật được đưa vào 0.3.85/1.3.3. Với manifest không đáng tin cậy, hãy dùng bản phát hành hiện tại và giới hạn `allowed_objects` ở các class message hoặc một danh sách an toàn cụ thể, đồng thời đặt `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> Đối với [lập bản đồ ranh giới tin cậy của agent](AI-Agent-Security-Methodology.md), hãy phân biệt điều này với [RCE khi tải tệp model](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT cung cấp các bản triển khai dễ đọc và quy trình làm việc qua dòng lệnh để pretraining, fine-tuning, đánh giá và triển khai các language model được hỗ trợ.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Mô tả:**\
LitServe là framework phục vụ model của Lightning AI, dùng để cung cấp API inference với các hook cho batching, streaming, tăng tốc và mở rộng quy mô.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl là framework post-training và fine-tuning mã nguồn mở, được điều khiển bằng cấu hình YAML. Framework này hỗ trợ các kỹ thuật như fine-tuning toàn bộ, LoRA/QLoRA, tối ưu hóa preference và huấn luyện đa GPU; bản thân nó không phải là nền tảng triển khai cloud.<sup>[[5]](#references)</sup>

## Dùng thử model trực tuyến

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** là một nền tảng và cộng đồng hàng đầu về machine learning, đặc biệt nổi tiếng với các đóng góp trong xử lý ngôn ngữ tự nhiên (NLP). Nền tảng này cung cấp các công cụ, thư viện và tài nguyên giúp việc phát triển, chia sẻ và triển khai model machine learning trở nên dễ dàng hơn.\
Hub có một số mục liên quan:<sup>[[6]](#references)</sup>

* **Models**: Kho lưu trữ rộng lớn các **model machine learning được pre-train**, nơi người dùng có thể duyệt, tải xuống và tích hợp model cho nhiều tác vụ như tạo văn bản, dịch thuật, nhận dạng hình ảnh, v.v.
* **Datasets:** **Bộ sưu tập dataset** toàn diện dùng để huấn luyện và đánh giá model. Mục này giúp dễ dàng truy cập nhiều nguồn dữ liệu đa dạng, cho phép người dùng tìm và sử dụng dữ liệu cho các dự án machine learning cụ thể.
* **Spaces:** Nền tảng lưu trữ và chia sẻ **ứng dụng machine learning tương tác** cùng các bản demo. Nền tảng này cho phép nhà phát triển **giới thiệu** model đang hoạt động, tạo giao diện thân thiện với người dùng và cộng tác với người khác bằng cách chia sẻ bản demo trực tiếp.

#### Kiểm tra log runtime của Space công khai

Mã trong repository của một Space công khai có thể cho biết ứng dụng ghi log những input và biến môi trường nào. Khi thực hiện đánh giá được ủy quyền, hãy kiểm tra luồng log **run** như một bề mặt riêng biệt với giao diện ứng dụng. Hugging Face có tài liệu về endpoint SSE cho log của Space; nghiên cứu cho thấy những người dùng Hub khác có thể đọc log của Space công khai và đôi khi log chứa API key, prompt của người dùng hoặc access token của Dev Mode được ghi trong URL của request. Token xuất hiện trong log chỉ đáng lo ngại nếu chế độ đặc quyền tương ứng vẫn được bật và token vẫn còn hiệu lực.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Sử dụng token của tài khoản Hub được cấp quyền của bạn; đây **không** phải là yêu cầu cung cấp secret của chủ sở hữu Space. Phản hồi là một luồng SSE (các dòng `data:`). Đối chiếu các giá trị bị lộ với mã của Space và runtime hiện tại thay vì cho rằng tên biến chứng minh giá trị của nó đã bị lộ. Đối với [endpoint Gradio hoặc model-runner tự host](AI-Exposed-Self-Hosted-AI-Services.md), hãy làm theo trang đó.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** là một kho lưu trữ và thư viện dành cho các thành phần mô hình đã huấn luyện có thể tái sử dụng, đặc biệt là các module được dùng thông qua TensorFlow/Keras. **Kaggle** cung cấp riêng notebook, bộ dữ liệu, cuộc thi và mô hình.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Bộ sưu tập khổng lồ các mô hình và thành phần mô hình được huấn luyện trước, cho phép người dùng duyệt, tải xuống và tích hợp module cho các tác vụ như phân loại hình ảnh, embedding văn bản, v.v.
* **Tutorials:** Hướng dẫn từng bước và ví dụ giúp người dùng triển khai và tinh chỉnh mô hình bằng TensorFlow Hub.
* **Documentation:** Hướng dẫn toàn diện và tài liệu tham khảo API giúp nhà phát triển sử dụng hiệu quả các tài nguyên của kho lưu trữ.

## [**Replicate**](https://replicate.com/home)

**Replicate** là một nền tảng được lưu trữ để chạy các mô hình machine learning đã đóng gói thông qua giao diện web hoặc API.<sup>[[8]](#references)</sup>

* **Models:** Kho lưu trữ các mô hình machine learning do cộng đồng đóng góp, cho phép người dùng duyệt, dùng thử và tích hợp mô hình vào ứng dụng với ít công sức nhất.
* **API access:** API cho phép gọi mô hình từ ứng dụng mà không cần vận hành hạ tầng inference bên dưới.

## Tấn công các dịch vụ AI tự host bị lộ

Để fingerprint và kiểm thử black-box các model runner tự host, công cụ tạo agent, giao diện demo ML, cụm compute và cơ sở dữ liệu vector, hãy xem [Dịch vụ AI tự host bị lộ](AI-Exposed-Self-Hosted-AI-Services.md).



## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Tài liệu Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Tài liệu Replicate](https://replicate.com/docs)
- [9] [Tài liệu Kaggle](https://www.kaggle.com/docs)
- [10] [Thông báo bảo mật về injection serialization của LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [Thông báo bảo mật về việc khôi phục đối tượng không an toàn của LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [API load và mô hình mối đe dọa của LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [API log của Hugging Face Spaces](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Space của bạn là khu vực của tôi: Rủi ro bảo mật của ứng dụng AI trên các model hub](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
