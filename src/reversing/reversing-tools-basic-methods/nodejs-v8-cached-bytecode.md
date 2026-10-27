# Khử obfuscation tĩnh bytecode cache của Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Dữ liệu cache của V8 là **biểu diễn phụ thuộc phiên bản và bị mất thông tin**, không phải mã nguồn JavaScript hay tệp thực thi native thông thường. Vì vậy, quy trình xử lý tĩnh hữu ích là: gỡ mọi lớp đóng gói bên ngoài, disassemble cache bằng bản build V8 tương ứng, chuyển mã thành mô hình pseudocode trung gian, rồi áp dụng các phép biến đổi có xét đến dependency mà không thực thi mẫu. [View8](https://github.com/suleram/View8) và [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) triển khai cách tiếp cận này cho các payload Node.js được bảo vệ bằng `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Thu thập và disassemble cache

Trước tiên, hãy kiểm tra preload/launcher thay vì cho rằng mọi tệp `.jsc` đều dùng cùng một wrapper. Ví dụ, launcher như `node.exe -r preflight.js app.jsc` sẽ thực thi `preflight.js` trước module chính; trong họ mẫu đã phân tích, preload gỡ một lớp Brotli. Sau khi giải nén, hãy xác định chính xác thế hệ Node.js/V8 từ runtime đi kèm. Cache được tạo bởi một phiên bản V8 có thể bị phiên bản khác từ chối hoặc giải mã sai, vì vậy hãy build hoặc lấy `v8dasm` đúng tag V8 đó và áp dụng các bản vá cần thiết cho View8 và việc in chuỗi.<sup>[[1]](#references)[[2]](#references)</sup>

Quy trình không thực thi của bộ công cụ là:<sup>[[2]](#references)</sup>

```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
  --inp app.jsc.disasm.txt --normalize \
  --out decompiled/app.dec.txt \
  --export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
  --out deobfuscated/app.deobf.txt \
  --export_format decompiled serialized
```

`--normalize` cung cấp cho các function được tạo ra các định danh ổn định giữa các lần chạy. Đầu ra dạng văn bản dùng để kiểm tra; object graph đã serialize cho phép các pass độc lập giữ nguyên mối quan hệ giữa function, declarer, scope và metadata. Đây **không phải JavaScript được tái dựng hay có thể chạy được**.<sup>[[1]](#references)[[2]](#references)</sup>

### Đọc pseudocode View8 như một IR

Các tên thường gặp là `func_<name>_0x<address>`, tham số là `a0...aN`, virtual register là `r0...rN`, và `ACCU` là accumulator của V8. `start` là root declarer, còn `Scope[...]`, global và dictionary mô hình hóa các giá trị được nested function capture hoặc chia sẻ. Đừng phân tích mọi biểu thức theo cú pháp JavaScript: chẳng hạn, `!r6 === "0"` của View8 biểu thị phép phủ định của toàn bộ phép so sánh (`r6 !== "0"`), điều này quan trọng khi dựng lại các nhánh.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuscation có xét dependency

Áp dụng các phép biến đổi theo thứ tự làm lộ ra những đầu vào cần thiết cho pass tiếp theo, rồi lặp lại quá trình propagation cho đến khi đầu ra ổn định. Thứ tự thực tế:<sup>[[1]](#references)[[2]](#references)</sup>

1. Duyệt phân cấp declarer và propagation các giá trị từ global, register, dictionary và tham chiếu `Scope[...]`.
2. Khôi phục đối số của string decoder và thay các lời gọi đã mã hóa bằng plaintext.
3. Gộp các đoạn string liền kề; các tên property và string xác định thứ tự dispatcher thu được sẽ mở khóa các pass tiếp theo.
4. Gỡ phẳng control flow, inline call proxy và wrapper atomic-operation, đồng thời phân giải tham chiếu function được lưu trong dictionary.
5. Chạy propagation lần nữa vì mỗi string, key hoặc proxy được phân giải có thể làm lộ thêm một lớp indirection.
6. Thu gọn các one-shot initialization thunk đã nhận diện và chỉ xóa helper chết sau khi các call site của chúng đã được phân giải.

### Khôi phục mảng string RC4 bị dịch chuyển theo kiểu black box

Một dạng bố trí phổ biến của `javascript-obfuscator` lưu các chunk RC4 được mã hóa Base64 trong một mảng. Các wrapper decoder cung cấp offset dạng số và key ngắn, đôi khi theo thứ tự đối số đảo ngược, rồi cộng hoặc trừ các hằng số được capture trong closure scope. Khi root decoder bị obfuscate quá nặng, hãy khôi phục thực nghiệm độ dịch chuyển chỉ số mảng chưa biết thay vì dựng lại toàn bộ function.<sup>[[1]](#references)</sup>

Với một mảng gồm `N` chunk và một số lời gọi đến cùng decoder:<sup>[[1]](#references)</sup>

```text
for each observed (numeric_argument, rc4_key):
    candidates = {}
    for shift in 0 .. N-1:
        index = apply_observed_sign(numeric_argument, shift)
        plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
        if plaintext passes encoding/printability checks:
            candidates.add(shift)
root_shift = intersection(candidate_sets)
```

Không chấp nhận phép dịch chỉ vì một kết quả giải mã duy nhất trông như văn bản in được: ciphertext sai vẫn có thể tình cờ tạo ra kết quả như vậy. Hãy dùng ít nhất ba quan sát riêng biệt và chỉ chấp nhận một phép dịch duy nhất tạo ra văn bản hợp lý trong tất cả các quan sát. Sau đó, duyệt đồ thị wrapper/declarer, cộng dồn từng phép cộng hoặc trừ và ghi lại liệu đối số số học có đứng trước hay không. Cache metadata này cho mỗi mẫu, thay thế các lệnh gọi decoder, nối các đoạn plaintext liền kề và xuất riêng các chuỗi để phân loại.<sup>[[1]](#references)[[2]](#references)</sup>

### Bảo toàn ngữ nghĩa khi gỡ flattening

Với các vòng lặp dispatcher điều khiển bằng chuỗi như `3|2|1|0|4`, hãy giải mã chuỗi thứ tự, ánh xạ từng phép so sánh state tới block tương ứng, xử lý ký pháp điều kiện phủ định của View8, rồi xuất các block theo thứ tự dispatcher. Một `continue` lồng bên trong có thể biểu thị một bước nhảy sớm trở lại dispatcher thay vì luồng thực thi tiếp diễn thông thường. Khi loại bỏ vòng lặp, hãy xóa `continue` đó và chuyển các câu lệnh vốn theo sau `if` bao quanh nó vào một nhánh `else` được tạo ra; chỉ xóa dispatcher sẽ làm thay đổi hành vi.<sup>[[1]](#references)</sup>

### Inline proxy, phép toán và lazy thunk

Chuẩn hóa các helper chuyển tiếp như `return a0(a1, a2)` trước khi thay các điểm gọi chúng bằng lệnh gọi trực tiếp. Xử lý tương tự các wrapper cho phép trừ, phép chia, phép so sánh, phép kiểm tra thành viên hoặc lời gọi hàm. Vì tham chiếu helper có thể nằm sau một khóa dictionary đã giải mã hoặc giá trị closure, hãy chạy lan truyền chuỗi và cấu trúc trước lẫn sau khi inline.<sup>[[1]](#references)</sup>

Cũng cần nhận diện các closure gọi một hàm đã lưu một lần, xóa tham chiếu tới hàm đó, cache kết quả rồi trả về cache trong các lần gọi sau. Rút gọn thunk này tại vị trí khởi tạo sẽ làm lộ dispatcher hoặc hàm capability bên dưới, nhưng cần chú thích rằng hoạt động ban đầu là **chỉ chạy một lần và được cache**, thay vì mô hình hóa mỗi lần gọi như một lần thực thi mới.<sup>[[1]](#references)</sup>

## Ghi chú về an toàn và kiểm định

- Việc tải Python `pickle` có thể thực thi code. Chỉ tải các tệp `.pkl` được tạo cục bộ bởi lần chạy View8 đáng tin cậy; không bao giờ coi pickle do mẫu cung cấp là dữ liệu.<sup>[[2]](#references)</sup>
- Các pass dựa trên pattern không phải là trình dịch ngược JavaScript tổng quát. Giữ nguyên các biểu thức chưa phân giải và kiểm tra thủ công các biến thể dispatcher không rõ ràng, thay vì ép viết lại chúng.<sup>[[1]](#references)[[2]](#references)</sup>
- Tên hàm có sự hỗ trợ của LLM chỉ là gợi ý để điều hướng, không phải bằng chứng. Nếu sử dụng chúng, hãy xử lý các dependency theo thứ tự leaf-first, nhưng xác minh mọi nhãn dựa trên nội dung hàm, đối số, chuỗi, luồng dữ liệu, API và side effect.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Breaking the Seal: Static Deobfuscation of JSCeal's Compiled V8 Bytecode](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
