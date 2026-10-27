# Steganography trong tài liệu

{{#include ../../banners/hacktricks-training.md}}

Nhiều định dạng tài liệu là các container có cấu trúc thay vì một luồng dữ liệu đơn lẻ:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (tệp nhúng, luồng)
- Office OOXML (`.docx/.xlsx/.pptx` là các tệp ZIP)
- Tài liệu RTF và OLE/Compound File Binary đời cũ. RTF lưu trữ các từ điều khiển và nhóm trong định dạng hướng văn bản, còn tệp OLE compound cung cấp cấu trúc phân cấp các đối tượng lưu trữ và luồng giống như hệ thống tệp; cả hai đều cần được kiểm tra theo định dạng cụ thể để tìm dữ liệu ẩn hoặc được nhúng.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Kỹ thuật

Tệp PDF có thể chứa các object, stream, JavaScript và tệp nhúng. Trong quá trình phân tích, các tác vụ phổ biến gồm:

- Trích xuất tệp đính kèm được nhúng.
- Mở rộng object stream để dễ kiểm tra các object hơn.
- Xác định JavaScript, hình ảnh được nhúng và các stream bất thường.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Kiểm tra nhanh

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

Kết hợp `--qdf --object-streams=disable` tạo ra biểu diễn dễ đọc hơn và loại bỏ object streams, giúp kiểm tra thủ công dễ dàng hơn.<sup>[[2]](#references)</sup> Sau đó, tìm các object và chuỗi đáng ngờ trong `out.pdf`.

## Office OOXML

### Kỹ thuật

Các tệp Office Open XML (`.docx`, `.xlsx` và `.pptx`) sử dụng Open Packaging Conventions: một gói dựa trên ZIP gồm các thành phần và tệp XML mô tả quan hệ.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Hãy xem gói này như một đồ thị quan hệ và kiểm tra media, các quan hệ bên ngoài và những thành phần tùy chỉnh bất thường.

Trên thực tế:

- Tài liệu là một cây thư mục gồm XML và tài nguyên.
- Các tệp mô tả quan hệ trong `_rels/` có thể trỏ đến tài nguyên bên ngoài hoặc các thành phần ẩn.
- Dữ liệu nhúng thường nằm trong `word/media/`, các thành phần XML tùy chỉnh hoặc những quan hệ bất thường.

### Kiểm tra nhanh

```bash
7z l file.docx
7z x file.docx -oout
```

Sau đó kiểm tra:

- `word/document.xml`
- `word/_rels/` để tìm các external relationship
- media được nhúng trong `word/media/`

## References

- [1] [Hướng dẫn sử dụng Poppler pdfdetach](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [Tài liệu qpdf - chế độ QDF và object stream](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Các kiến thức cơ bản về Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Định dạng tệp Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Giới thiệu về định dạng tệp Compound File Binary](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - Tài liệu tham khảo về đặc tả RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
