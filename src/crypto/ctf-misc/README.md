# Crypto CTF Misc

{{#include ../../banners/hacktricks-training.md}}

Phần này tập hợp các kỹ thuật xuất hiện trong thử thách cryptography nhưng không phù hợp với các danh mục khác.

## Ngôn ngữ lập trình dị biệt

### Kỹ thuật

Dùng quy trình này khi thử thách yêu cầu chạy chương trình viết bằng ngôn ngữ lập trình dị biệt và giải mã đầu ra.

Nếu thử thách cung cấp đoạn code không giống ngôn ngữ lập trình thông dụng:

- Xác định ngôn ngữ bằng cách tìm kiếm token hoặc chuỗi lệnh đặc trưng.
- Dùng trình thông dịch trực tuyến hoặc Docker image.
- Nếu đầu ra trông kỳ lạ, hãy kiểm tra xem sau khi thực thi có lớp encoding hoặc compression nào không.

Esolang wiki là một danh mục ngôn ngữ hữu ích.<sup>[[1]](#references)</sup> Với các lớp encoding và compression thông thường, hãy dùng [Crypto CTF workflow](../ctf-workflow/). Nếu manh mối là văn bản ẩn thay vì cú pháp có thể thực thi, hãy xem [text steganography](../../stego/text/).

### Trích xuất trạng thái interpreter được nạp sẵn

Nếu thử thách chấp nhận source code của ngôn ngữ lập trình dị biệt và chạy trong **custom interpreter**, hãy kiểm tra bộ nhớ ban đầu, stack và các lệnh output trước khi xem source code như một câu đố giải mã. Khi interpreter nạp sẵn secret lên stack của Befunge, một chương trình ngắn có thể pop và in các byte hiện có mà không cần tính toán chúng. Cách này cần quyền kiểm soát source code được thực thi và một opcode output; nó không hoạt động với interpreter thông thường có trạng thái ban đầu rỗng. Trong một thử thách Befunge, input bên dưới liên tục in ra các ký tự từ flag được nạp sẵn lên stack theo thứ tự ngược.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` bắt đầu thực thi sang phải, `,` lấy một ký tự khỏi ngăn xếp và in ra, còn `<` đưa con trỏ lệnh trở lại `,`. Hãy kiểm tra cách trình thông dịch tùy chỉnh xử lý tình trạng thiếu phần tử trong ngăn xếp và giới hạn lệnh: bản triển khai được trích dẫn sẽ dừng khi ngăn xếp cạn hoặc sau 1.024 lệnh. Nếu bí mật không nằm trực tiếp trên ngăn xếp, hãy kiểm tra các trạng thái khác được khởi tạo và những lệnh xuất/đọc có sẵn, thay vì mặc định rằng ngữ nghĩa của Befunge tiêu chuẩn được áp dụng.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, wiki về các ngôn ngữ lập trình kỳ quặc](https://esolangs.org/wiki/Main_Page)
- [2] [Bài writeup gốc của WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [Mã nguồn trình thông dịch Befuddled1 của WolvCTF 2024](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Tài liệu tham khảo ngôn ngữ Befunge](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
