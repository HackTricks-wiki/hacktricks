# Công cụ và nền tảng cho mô hình AI

{{#include ../banners/hacktricks-training.md}}

## Chạy và huấn luyện mô hình trên máy cục bộ

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers là thư viện mã nguồn mở để tải, huấn luyện và cung cấp các mô hình đã được huấn luyện trước cho các tác vụ về văn bản, hình ảnh, âm thanh, video và đa phương thức. Việc lưu trữ mô hình và tập dữ liệu được Hugging Face Hub cung cấp riêng.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain là framework để xây dựng các ứng dụng và agent dựa trên mô hình, với các tính năng tạo prompt, quản lý lịch sử hội thoại/trạng thái, tích hợp công cụ, truy xuất, mô hình, API và cơ sở dữ liệu.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT cung cấp các bản triển khai dễ đọc và quy trình làm việc qua dòng lệnh để pretrain, fine-tune, đánh giá và triển khai các mô hình ngôn ngữ được hỗ trợ.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Mô tả:**\
LitServe là framework phục vụ mô hình của Lightning AI, cho phép cung cấp API inference với các hook hỗ trợ batching, streaming, tăng tốc và mở rộng quy mô.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl là framework mã nguồn mở cho post-training và fine-tuning, được cấu hình bằng YAML. Framework hỗ trợ các kỹ thuật như fine-tuning toàn phần, LoRA/QLoRA, tối ưu hóa theo sở thích và huấn luyện đa GPU; bản thân nó không phải là nền tảng triển khai cloud.<sup>[[5]](#references)</sup>

## Dùng thử mô hình trực tuyến

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** là một nền tảng và cộng đồng hàng đầu về machine learning, đặc biệt nổi tiếng với các hoạt động trong lĩnh vực xử lý ngôn ngữ tự nhiên (NLP). Nền tảng này cung cấp công cụ, thư viện và tài nguyên giúp việc phát triển, chia sẻ và triển khai mô hình machine learning dễ dàng hơn.\
Hub có một số mục liên quan sau:<sup>[[6]](#references)</sup>

* **Mô hình**: Kho lưu trữ rộng lớn các **mô hình machine learning đã được huấn luyện trước**, nơi người dùng có thể duyệt, tải xuống và tích hợp mô hình cho nhiều tác vụ như tạo văn bản, dịch thuật, nhận dạng hình ảnh, v.v.
* **Tập dữ liệu:** **Bộ sưu tập tập dữ liệu** toàn diện dùng để huấn luyện và đánh giá mô hình. Mục này giúp truy cập dễ dàng vào nhiều nguồn dữ liệu, cho phép người dùng tìm và sử dụng dữ liệu phù hợp với các dự án machine learning cụ thể.
* **Spaces:** Nền tảng lưu trữ và chia sẻ **các ứng dụng machine learning tương tác** và bản demo. Nền tảng này cho phép nhà phát triển **giới thiệu** mô hình đang hoạt động, tạo giao diện thân thiện với người dùng và cộng tác với người khác bằng cách chia sẻ bản demo trực tiếp.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** là kho lưu trữ và thư viện các thành phần mô hình đã huấn luyện có thể tái sử dụng, đặc biệt là các module được dùng thông qua TensorFlow/Keras. **Kaggle** cung cấp riêng notebook, tập dữ liệu, cuộc thi và mô hình.<sup>[[7]](#references)[[9]](#references)</sup>

* **Module:** Bộ sưu tập lớn các mô hình đã được huấn luyện trước và thành phần mô hình, nơi người dùng có thể duyệt, tải xuống và tích hợp module cho các tác vụ như phân loại hình ảnh, nhúng văn bản, v.v.
* **Hướng dẫn:** Hướng dẫn từng bước và ví dụ giúp người dùng triển khai và fine-tune mô hình bằng TensorFlow Hub.
* **Tài liệu:** Hướng dẫn toàn diện và tài liệu tham khảo API giúp nhà phát triển sử dụng hiệu quả các tài nguyên của kho lưu trữ.

## [**Replicate**](https://replicate.com/home)

**Replicate** là nền tảng được lưu trữ để chạy các mô hình machine learning đã đóng gói thông qua giao diện web hoặc API.<sup>[[8]](#references)</sup>

* **Mô hình:** Kho lưu trữ các mô hình machine learning do cộng đồng đóng góp, cho phép người dùng duyệt, dùng thử và tích hợp mô hình vào ứng dụng một cách dễ dàng.
* **Truy cập API:** API cho phép gọi mô hình từ ứng dụng mà không cần vận hành hạ tầng inference bên dưới.

## Tấn công các dịch vụ AI tự lưu trữ bị lộ

Để fingerprint và kiểm tra black-box các trình chạy mô hình, công cụ xây dựng agent, giao diện demo ML, cụm tính toán và cơ sở dữ liệu vector tự lưu trữ, hãy xem [Các dịch vụ AI tự lưu trữ bị lộ](AI-Exposed-Self-Hosted-AI-Services.md).

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
{{#include ../banners/hacktricks-training.md}}
