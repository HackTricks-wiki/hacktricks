# Phân tích tệp Office

{{#include ../../../banners/hacktricks-training.md}}

Để biết thêm thông tin, hãy xem [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Đây chỉ là bản tóm tắt:<sup>[[4]](#references)</sup>

Tài liệu Microsoft Office thường có các định dạng cũ như RTF và DOC, XLS, PPT dựa trên OLE/CFBF, hoặc các định dạng **Office Open XML (OOXML)** mới hơn như DOCX, XLSX và PPTX. Tài liệu Office có thể chứa nội dung chủ động như macro, khiến chúng thường được dùng để phát tán phishing và malware. Tệp OOXML là các container ZIP, có thể kiểm tra cấu trúc phân cấp tệp và nội dung XML bằng cách giải nén.<sup>[[3]](#references)[[4]](#references)</sup>

Các lệnh giải nén tài liệu và cấu trúc đầu ra được cung cấp để khám phá cấu trúc tệp OOXML. Các kỹ thuật ẩn dữ liệu trong những tệp này đã được ghi nhận, cho thấy việc che giấu dữ liệu trong các thử thách CTF vẫn không ngừng đổi mới.<sup>[[4]](#references)</sup>

Để phân tích, **oletools** và **OfficeDissector** cung cấp bộ công cụ toàn diện để kiểm tra cả tài liệu OLE lẫn OOXML. Những công cụ này giúp xác định và phân tích các macro được nhúng, vốn thường là phương thức phát tán malware; các macro này thường tải xuống và thực thi thêm payload độc hại. Có thể phân tích macro VBA mà không cần Microsoft Office bằng Libre Office, cho phép debug bằng breakpoint và biến theo dõi.<sup>[[4]](#references)</sup>

Cài đặt và sử dụng **oletools** khá đơn giản; các lệnh cài đặt qua pip và trích xuất macro từ tài liệu cũng được cung cấp. Trong Word, các macro tự động bao gồm `AutoExec` và `AutoOpen`, còn `Document_Open` là một thủ tục xử lý sự kiện mở tài liệu.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Đối với tài liệu Office được mã hóa bằng mật khẩu, xem [quy trình khôi phục offline dựa trên grammar](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Khai thác OLE Compound File: Autodesk Revit RFA – tính toán lại ECC và gzip có kiểm soát

Các mô hình Revit RFA được lưu dưới dạng [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (còn gọi là CFBF). Mô hình đã tuần tự hóa nằm trong storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Bố cục chính của `Global\Latest` (quan sát trên Revit 2025):

- Header
- Payload được nén bằng GZIP (đồ thị đối tượng đã tuần tự hóa thực tế)
- Padding bằng các byte 0
- Phần cuối chứa Mã sửa lỗi (ECC)

Revit sẽ tự động sửa các thay đổi nhỏ trong stream bằng phần cuối ECC và từ chối các stream không khớp với ECC. Vì vậy, việc chỉnh sửa trực tiếp các byte đã nén sẽ không có hiệu lực: thay đổi của bạn либо bị hoàn tác, hoặc tệp bị từ chối. Để đảm bảo kiểm soát chính xác từng byte mà bộ giải tuần tự nhìn thấy, bạn phải:<sup>[[1]](#references)</sup>

- Nén lại bằng cách triển khai gzip tương thích với Revit (để các byte đã nén do Revit tạo ra/chấp nhận khớp với định dạng mong đợi).
- Tính toán lại phần cuối ECC trên stream đã được đệm để Revit chấp nhận stream đã chỉnh sửa mà không tự động sửa chữa.

Quy trình thực tế để vá/fuzz nội dung RFA:<sup>[[1]](#references)</sup>

1) Mở rộng tài liệu OLE compound.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Chỉnh sửa Global\Latest theo đúng quy trình gzip/ECC

- Phân tích `Global/Latest`: giữ nguyên header, gunzip payload, thay đổi các byte, rồi gzip lại bằng các tham số deflate tương thích với Revit.
- Giữ nguyên zero-padding và tính lại trailer ECC để Revit chấp nhận các byte mới.
- Nếu cần tái tạo byte-for-byte một cách xác định, hãy tạo một wrapper tối giản quanh các DLL của Revit để gọi các hàm gzip/gunzip và tính ECC (như đã trình bày trong nghiên cứu), hoặc dùng lại helper có sẵn để tái tạo các ngữ nghĩa này.

3) Tạo lại tài liệu compound OLE.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Ghi chú:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool ghi storages/streams vào filesystem, đồng thời escape các ký tự không hợp lệ trong tên NTFS; đường dẫn stream cần tìm chính xác là `Global/Latest` trong cây đầu ra.
- Khi triển khai tấn công quy mô lớn thông qua các plugin trong hệ sinh thái lấy RFA từ cloud storage, hãy đảm bảo RFA đã vá vượt qua các kiểm tra toàn vẹn cục bộ của Revit (gzip/ECC chính xác) trước khi thử injection qua mạng.

Thông tin khai thác (để định hướng các byte cần đặt trong payload gzip):<sup>[[1]](#references)</sup>

- Bộ giải tuần tự của Revit đọc chỉ mục lớp 16-bit rồi khởi tạo một object. Một số kiểu nhất định không đa hình và không có vtable; lợi dụng cách xử lý destructor sẽ tạo ra type confusion, khiến engine thực thi một indirect call thông qua con trỏ do attacker kiểm soát.
- Chọn `AString` (chỉ mục lớp `0x1F`) sẽ đặt một con trỏ heap do attacker kiểm soát tại offset 0 của object. Trong vòng lặp destructor, Revit thực chất thực thi:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Đặt nhiều object như vậy trong serialized graph để mỗi vòng lặp của destructor thực thi một gadget (“weird machine”), rồi bố trí stack pivot vào một ROP chain x64 thông thường.

Xem chi tiết về pivot/gadget trên Windows x64 tại đây:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

và hướng dẫn chung về ROP tại đây:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Công cụ:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) để giải nén/tái dựng các file OLE compound: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD để reverse/taint; tắt page heap với TTD để giữ trace gọn.
- Có thể dùng proxy cục bộ (ví dụ Fiddler) để mô phỏng việc phân phối qua chuỗi cung ứng bằng cách thay RFAs trong lưu lượng plugin nhằm kiểm thử.

## References

- [1] [Tạo một exploit RCE hoàn chỉnh từ crash trong quá trình phân tích cú pháp file RFA của Autodesk Revit (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Tài liệu về OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Cẩm nang thực địa Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Tài liệu olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Sự kiện Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
