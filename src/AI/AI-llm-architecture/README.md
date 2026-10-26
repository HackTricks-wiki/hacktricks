# Huấn luyện LLM - Chuẩn bị dữ liệu

{{#include ../../banners/hacktricks-training.md}}

**Đây là ghi chú của tôi từ cuốn sách rất đáng đọc** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **cùng một số thông tin bổ sung.**<sup>[[1]](#references)</sup>

## Thông tin cơ bản

Bạn nên bắt đầu bằng cách đọc bài viết này để nắm một số khái niệm cơ bản cần biết:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> Mục tiêu của giai đoạn này là **chia đầu vào thành các token và ánh xạ chúng sang các token ID**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Lấy mẫu dữ liệu

> [!TIP]
> Mục tiêu của giai đoạn này là chuẩn bị các chuỗi huấn luyện có độ dài ngữ cảnh được chọn, cùng với các mục tiêu dự đoán đã dịch chuyển tương ứng.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Embedding token

> [!TIP]
> Mục tiêu của giai đoạn thứ ba này rất đơn giản: **Gán cho mỗi token trong từ vựng một vector có số chiều mong muốn để huấn luyện mô hình.** Mỗi từ trong từ vựng sẽ là một điểm trong không gian X chiều.\
> Lưu ý rằng ban đầu, vị trí của mỗi từ trong không gian chỉ được khởi tạo một cách "ngẫu nhiên", và các vị trí này là những tham số có thể huấn luyện (sẽ được cải thiện trong quá trình huấn luyện).
>
> Ngoài ra, trong quá trình embedding token, **một lớp embedding khác được tạo ra** để biểu diễn (trong trường hợp này) **vị trí tuyệt đối của từ trong câu huấn luyện**. Nhờ vậy, một từ ở các vị trí khác nhau trong câu sẽ có biểu diễn khác nhau.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Cơ chế attention

> [!TIP]
> Mục tiêu của giai đoạn thứ tư này rất đơn giản: **Áp dụng một số cơ chế attention**. Các cơ chế này sẽ gồm nhiều **lớp lặp lại**, giúp **nắm bắt mối quan hệ giữa một từ trong từ vựng với các từ lân cận trong câu hiện tại đang được dùng để huấn luyện LLM**.\
> Có nhiều lớp được sử dụng cho việc này, vì vậy sẽ có nhiều tham số có thể huấn luyện dùng để nắm bắt thông tin này.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Kiến trúc LLM

> [!TIP]
> Mục tiêu của giai đoạn thứ năm này rất đơn giản: **Xây dựng kiến trúc hoàn chỉnh của LLM**. Kết hợp mọi thứ, áp dụng tất cả các lớp và tạo mọi hàm cần thiết để tạo văn bản hoặc chuyển đổi văn bản thành ID và ngược lại.
>
> Kiến trúc này sẽ được dùng cả khi huấn luyện lẫn khi dự đoán văn bản sau khi mô hình đã được huấn luyện.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training và tải mô hình

> [!TIP]
> Mục tiêu của giai đoạn thứ sáu này rất đơn giản: **Huấn luyện mô hình từ đầu**. Để làm vậy, kiến trúc LLM ở phần trước sẽ được dùng cùng với các vòng lặp chạy qua các tập dữ liệu, sử dụng các hàm loss và optimizer đã xác định để huấn luyện toàn bộ tham số của mô hình.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Cải thiện LoRA trong fine-tuning

> [!TIP]
> LoRA giúp giảm đáng kể số lượng tham số có thể huấn luyện và trạng thái optimizer cần thiết để fine-tune một mô hình đã được pre-train.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-tuning cho phân loại

> [!TIP]
> Mục tiêu của phần này là trình bày cách fine-tune một mô hình đã được pre-train để thay vì tạo văn bản mới, LLM sẽ đưa ra **xác suất văn bản đầu vào thuộc từng danh mục được cung cấp** (chẳng hạn như văn bản có phải là spam hay không).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-tuning để làm theo hướng dẫn

> [!TIP]
> Mục tiêu của phần này là trình bày cách **fine-tune một mô hình đã được pre-train để làm theo hướng dẫn**, thay vì chỉ tạo văn bản; ví dụ như trả lời các yêu cầu với vai trò chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
