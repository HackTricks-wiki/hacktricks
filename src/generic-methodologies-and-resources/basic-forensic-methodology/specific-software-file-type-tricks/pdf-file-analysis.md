# Phân tích file PDF

{{#include ../../../banners/hacktricks-training.md}}

**Để biết thêm chi tiết, hãy xem:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Định dạng PDF nổi tiếng vì độ phức tạp và khả năng che giấu dữ liệu, khiến nó trở thành trọng tâm trong các thử thách CTF forensics. Định dạng này kết hợp các thành phần văn bản thuần với các đối tượng nhị phân, có thể được nén hoặc mã hóa, đồng thời có thể chứa các script bằng những ngôn ngữ như JavaScript hoặc Flash. Để tìm hiểu cấu trúc PDF, bạn có thể tham khảo [tài liệu giới thiệu](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) của Didier Stevens hoặc dùng các công cụ như trình soạn thảo văn bản hay trình soạn thảo chuyên dụng cho PDF như Origami.

Để khám phá hoặc thao tác PDF chuyên sâu, có thể dùng các công cụ như [qpdf](https://github.com/qpdf/qpdf) và [Origami](https://github.com/mobmewireless/origami-pdf). Dữ liệu ẩn trong PDF có thể được giấu ở:

- Các lớp vô hình
- Định dạng metadata XMP của Adobe
- Các phiên bản tăng dần
- Văn bản có màu trùng với màu nền
- Văn bản nằm sau hình ảnh hoặc các hình ảnh chồng lấp
- Các bình luận không được hiển thị

Để phân tích PDF tùy chỉnh, có thể dùng các thư viện Python như [PeepDF](https://github.com/jesparza/peepdf) để tạo các script phân tích riêng. Hơn nữa, PDF có tiềm năng lưu trữ dữ liệu ẩn rất lớn, nên các tài liệu như hướng dẫn của NSA về rủi ro PDF và biện pháp đối phó vẫn cung cấp nhiều thông tin hữu ích, dù hiện không còn được lưu trữ tại địa chỉ ban đầu. Bạn có thể đọc thêm về chủ đề này trong [bản sao hướng dẫn](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) và bộ sưu tập [các thủ thuật định dạng PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) của Ange Albertini.<sup>[[4]](#references)[[5]](#references)</sup>

## Các cấu trúc độc hại thường gặp

Kẻ tấn công thường lạm dụng một số đối tượng và hành động PDF cụ thể, được tự động thực thi khi tài liệu được mở hoặc khi người dùng tương tác với nó. Các từ khóa đáng chú ý:

* **/OpenAction, /AA** – hành động tự động được thực thi khi mở tài liệu hoặc khi xảy ra các sự kiện cụ thể.
* **/JS, /JavaScript** – JavaScript được nhúng (thường bị làm rối hoặc chia thành nhiều đối tượng).
* **/Launch, /SubmitForm, /URI, /GoToE** – trình khởi chạy tiến trình bên ngoài / URL.
* **/RichMedia, /Flash, /3D** – các đối tượng đa phương tiện có thể che giấu payload.
* **/EmbeddedFile /Filespec** – tệp đính kèm (EXE, DLL, OLE, v.v.).
* **/ObjStm, /XFA, /AcroForm** – các luồng đối tượng hoặc biểu mẫu thường bị lạm dụng để che giấu shellcode.
* **Các bản cập nhật tăng dần** – nhiều dấu `%%EOF` hoặc giá trị offset **/Prev** rất lớn có thể cho thấy dữ liệu được nối thêm sau khi ký nhằm vượt qua AV.

Khi bất kỳ token nào ở trên xuất hiện cùng với các chuỗi đáng ngờ (powershell, cmd.exe, calc.exe, base64, v.v.), PDF đó cần được phân tích sâu hơn.

---

## Tóm tắt phân tích tĩnh

Các ví dụ dưới đây sử dụng giao diện dòng lệnh được tài liệu hóa của `pdf-parser.py`, qpdf và pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```

Pixelating một hình ảnh bên trong PDF không xóa các pixel bên dưới. Nếu một tài liệu có thể đọc được dường như che giấu thông tin xác thực theo cách này, hãy trích xuất hình ảnh được nhúng để kiểm tra ngoại tuyến trong phạm vi được ủy quyền; kết quả phụ thuộc vào hình ảnh và tài liệu tham chiếu phù hợp, và không đảm bảo có thể khôi phục bằng mắt. Mật khẩu khôi phục được vẫn cần được xác minh riêng với tài khoản có đặc quyền cần thiết. Không đưa quy trình trích xuất PDF hoặc khôi phục hình ảnh vào quy trình quét liệt kê máy chủ thông thường.

Một số dự án hữu ích khác (được duy trì tích cực trong giai đoạn 2023-2025):
* **pdfcpu** – thư viện/CLI Go có thể xác thực, giải mã, trích xuất, tối ưu hóa và thao tác với PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – công cụ trực quan hóa chạy trên trình duyệt, hiển thị đồ thị đối tượng và các luồng dữ liệu.
* **PyMuPDF** – các binding Python có thể lập trình để kiểm tra PDF và render trang thành ảnh raster. Hãy xem parser/renderer là bề mặt tấn công từ tệp không đáng tin cậy và chạy chúng trong môi trường phân tích được cô lập phù hợp.<sup>[[8]](#references)</sup>

---

## Các kỹ thuật tấn công gần đây (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC đã báo cáo một kỹ thuật nối thêm tệp MHT được tạo bằng Word, chứa macro VBA, vào PDF; tệp vẫn giữ magic của PDF nhưng đồng thời cũng mở được bằng Word. Các công cụ chỉ phân tích PDF, sandbox hoặc antivirus có thể bỏ sót macro vì hành vi độc hại xảy ra khi tệp được mở bằng Word; hãy tìm dấu đánh dấu `<w:WordDocument>` cùng với các dấu hiệu MHT khác.<sup>[[2]](#references)</sup>
* **Shadow attacks trên PDF đã ký** – kẻ tấn công có thể đặt nội dung ẩn trong PDF trước khi tệp được ký, sau đó nối thêm một bản cập nhật tăng dần để thay đổi catalog hoặc tham chiếu đối tượng, khiến trình xem hiển thị nội dung ẩn trong khi chữ ký gốc vẫn hợp lệ. Kỹ thuật này có thể qua mặt các trình xem phân loại những bản cập nhật như vậy là vô hại.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe đánh giá lỗ hổng nghiêm trọng này là lỗi use-after-free có thể dẫn đến thực thi mã tùy ý; APSB24-29 được công bố vào ngày 14 tháng 5 năm 2024.<sup>[[3]](#references)</sup>

---

## Mẫu quy tắc YARA nhanh

```yara
rule Suspicious_PDF_AutoExec {
    meta:
        description = "Generic detection of PDFs with auto-exec actions and JS"
        author      = "HackTricks"
        last_update = "2025-07-20"
    strings:
        $pdf_magic = { 25 50 44 46 }          // %PDF
        $aa        = "/AA" ascii nocase
        $openact   = "/OpenAction" ascii nocase
        $js        = "/JS" ascii nocase
    condition:
        $pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```

---

## Mẹo phòng thủ

1. **Vá nhanh** – luôn cập nhật Acrobat/Reader lên phiên bản mới nhất của Continuous track; hầu hết chuỗi RCE được quan sát ngoài thực tế đều khai thác các lỗ hổng n-day đã được vá từ nhiều tháng trước.
2. **Loại bỏ nội dung chủ động tại gateway** – sử dụng công cụ sanitizer chuyên dụng, có chính sách kiểm soát, hoặc sản phẩm CDR có chức năng loại bỏ rõ ràng JavaScript, tệp nhúng, hành động khởi chạy, biểu mẫu và nội dung đa phương tiện. `qpdf --qdf` giúp kiểm tra các object PDF dễ dàng hơn, còn pdfcpu cung cấp các tính năng xác thực và thao tác; bản thân mỗi lệnh đều không chứng minh được rằng nội dung chủ động đã bị loại bỏ.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – chuyển PDF thành hình ảnh (hoặc PDF/A) trên host sandbox để giữ nguyên hình thức hiển thị đồng thời loại bỏ các object chủ động.
4. **Chặn các tính năng ít được sử dụng** – cài đặt “Enhanced Security” dành cho doanh nghiệp trong Reader cho phép tắt JavaScript, nội dung đa phương tiện và kết xuất 3D.
5. **Đào tạo người dùng** – social engineering (dụ dỗ bằng hóa đơn và hồ sơ xin việc) vẫn là vector tấn công ban đầu; hướng dẫn nhân viên chuyển tiếp các tệp đính kèm đáng ngờ cho IR.

## References

- [1] [Hướng dẫn thực địa CTF về pháp chứng](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc trong PDF – Vượt qua cơ chế phát hiện bằng cách nhúng tệp Word độc hại vào tệp PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Bản tin bảo mật Adobe – Có bản cập nhật bảo mật cho Adobe Acrobat và Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - bản sao của hướng dẫn](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - các thủ thuật về định dạng PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Tấn công Shadow: Ẩn và thay thế nội dung trong PDF đã ký](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Hướng dẫn PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Tùy chọn dòng lệnh qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
