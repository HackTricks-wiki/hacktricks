# Khử obfuscation tĩnh bytecode cache của Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Dữ liệu cache của V8 là **một dạng biểu diễn phụ thuộc phiên bản và bị mất thông tin**, không phải mã nguồn JavaScript hay tệp thực thi native thông thường. Vì vậy, quy trình tĩnh hữu ích là: gỡ lớp đóng gói bên ngoài, disassemble cache bằng bản build V8 tương ứng, chuyển đổi thành mô hình pseudocode trung gian, rồi áp dụng các phép biến đổi có xét đến dependency mà không thực thi mẫu. [View8](https://github.com/suleram/View8) và [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) triển khai phương pháp này cho payload Node.js được bảo vệ bằng `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Thu thập và disassemble cache

Trước tiên, hãy kiểm tra preload/launcher thay vì cho rằng mọi tệp `.jsc` đều có cùng wrapper. Ví dụ, launcher như `node.exe -r preflight.js app.jsc` sẽ chạy `preflight.js` trước module chính; trong nhóm mẫu được phân tích, preload đã gỡ một lớp Brotli. Sau khi giải nén, hãy xác định chính xác thế hệ Node.js/V8 từ runtime đi kèm. Cache được tạo bởi một phiên bản V8 có thể bị phiên bản khác từ chối hoặc giải mã sai, vì vậy hãy build hoặc lấy `v8dasm` dành cho đúng V8 tag đó và áp dụng các bản vá View8 cùng bản vá in chuỗi cần thiết.<sup>[[1]](#references)[[2]](#references)</sup>

Quy trình không thực thi của toolkit là:<sup>[[2]](#references)</sup>

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

`--normalize` cung cấp các mã định danh ổn định cho hàm được tạo ra giữa các lần chạy. Đầu ra dạng văn bản dùng để kiểm tra; đồ thị đối tượng được tuần tự hóa cho phép các pass độc lập bảo toàn mối quan hệ giữa hàm, nơi khai báo, scope và metadata. Đây **không phải JavaScript được tái dựng hay có thể chạy được**.<sup>[[1]](#references)[[2]](#references)</sup>

### Phân loại cache mà không cần build V8

Với cache thô hoặc được bọc Brotli, `jscd` có thể nhận diện header và liệt kê các hằng số cùng hàm mà không cần tải mẫu trong Node.js. Hãy dùng công cụ này trước để kiểm tra xem các bảng phiên bản có hỗ trợ file hay không, đồng thời ưu tiên các hàm trước khi chạy những pass giải mã obfuscation chuyên biệt hơn của View8.<sup>[[4]](#references)</sup>

Version hash là gợi ý nhận diện, không phải bằng chứng cho thấy một disassembler độc lập có cùng flags hoặc snapshot chỉ đọc như trình tạo ra nó.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` tạo listing tương thích với View8, nên lệnh View8 ở trên có thể dùng đầu ra đó thay cho `v8dasm` khi cache được hỗ trợ. Kiểm tra strings cùng với cây function để tìm các lời gọi decoder và những entry point có khả năng; không coi đầu ra JavaScript gần đúng của `jscd` là source gốc. Nếu công cụ từ chối version hoặc để lại các placeholder của read-only-heap, hãy quay lại bản dựng V8 tương ứng hoặc cung cấp name map từ cùng bản dựng, thay vì đoán tên property.<sup>[[4]](#references)</sup>

Với cache bên trong ứng dụng Electron, trước tiên hãy [extract ASAR và kiểm tra các entry point main và preload](../../desktop-application-security/electron-desktop-apps/). Cache Electron và Node có thể khác nhau về bố cục snapshot và pointer-compression ngay cả khi chuỗi version V8 của chúng trùng nhau.<sup>[[4]](#references)</sup>

### Đọc pseudocode View8 dưới dạng IR

Các tên thường có dạng `func_<name>_0x<address>`, các argument là `a0...aN`, virtual register là `r0...rN`, còn `ACCU` là accumulator của V8. `start` là declarer gốc, trong khi `Scope[...]`, globals và dictionaries mô hình hóa các giá trị được nested function capture hoặc chia sẻ. Đừng phân tích mọi biểu thức như cú pháp JavaScript: chẳng hạn, `!r6 === "0"` của View8 biểu thị phép phủ định của toàn bộ phép so sánh (`r6 !== "0"`), điều này quan trọng khi dựng lại các nhánh.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuscation nhận biết dependency

Áp dụng các phép biến đổi theo thứ tự giúp làm lộ đầu vào cần thiết cho pass tiếp theo, và lặp lại quá trình propagation cho đến khi đầu ra ổn định. Một thứ tự thực tế là:<sup>[[1]](#references)[[2]](#references)</sup>

1. Duyệt hệ thống phân cấp declarer và propagation các giá trị từ globals, registers, dictionaries và tham chiếu `Scope[...]`.
2. Khôi phục argument của string-decoder và thay các lời gọi đã mã hóa bằng plaintext.
3. Gộp các string chunk liền kề; các tên property và chuỗi thứ tự dispatcher thu được sẽ mở khóa những pass tiếp theo.
4. Làm phẳng control flow, inline call proxy và wrapper atomic-operation, đồng thời phân giải các tham chiếu function được lưu trong dictionary.
5. Propagation lần nữa vì mỗi string, key hoặc proxy được phân giải có thể làm lộ thêm một lớp indirection.
6. Chỉ thu gọn các one-shot initialization thunk đã nhận diện và xóa helper không dùng sau khi các call site của chúng đã được phân giải.

### Khôi phục mảng string RC4 bị dịch chuyển dưới dạng black box

Một bố cục phổ biến của `javascript-obfuscator` lưu các chunk RC4 được mã hóa Base64 trong một mảng. Các wrapper decoder cung cấp offset dạng số và key ngắn, đôi khi đảo ngược thứ tự argument, rồi cộng hoặc trừ các hằng số được capture trong closure scope. Khi root decoder bị obfuscate quá nặng, hãy khôi phục thực nghiệm độ dịch chỉ số chưa biết của mảng thay vì dựng lại toàn bộ function.<sup>[[1]](#references)</sup>

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

Không chấp nhận một shift chỉ dựa trên một kết quả giải mã có thể in được: ciphertext sai vẫn có thể tình cờ tạo ra kết quả có thể in. Hãy dùng ít nhất ba quan sát riêng biệt và chỉ chấp nhận một shift duy nhất tạo ra văn bản hợp lý trong tất cả các quan sát. Sau đó duyệt đồ thị wrapper/declarer, cộng dồn từng phép cộng hoặc trừ và ghi lại đối số số học có đứng trước hay không. Cache metadata này cho từng mẫu, thay các lời gọi decoder, nối các đoạn plaintext liền kề và xuất riêng các chuỗi để triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Giữ nguyên ngữ nghĩa khi gỡ flatten

Với các dispatcher loop được điều khiển bằng những chuỗi như `3|2|1|0|4`, hãy giải mã chuỗi thứ tự, ánh xạ từng phép so sánh trạng thái đến block tương ứng, tính đến ký hiệu điều kiện phủ định của View8, rồi xuất các block theo thứ tự dispatcher. Một `continue` lồng nhau có thể biểu thị một bước nhảy sớm trở lại dispatcher, chứ không phải luồng thực thi tiếp tục thông thường. Khi loại bỏ loop, hãy xóa `continue` đó và chuyển các câu lệnh vốn theo sau `if` bao quanh nó vào một nhánh `else` được tạo ra; chỉ xóa dispatcher sẽ làm thay đổi hành vi.<sup>[[1]](#references)</sup>

### Inline proxy, operation và lazy thunk

Chuẩn hóa các helper chuyển tiếp như `return a0(a1, a2)` trước khi thay các call site của chúng bằng lời gọi trực tiếp. Xử lý tương tự các wrapper cho phép trừ, phép chia, phép so sánh, phép kiểm tra membership hoặc lời gọi hàm. Vì bản thân tham chiếu đến helper có thể được lưu phía sau một khóa dictionary đã giải mã hoặc một giá trị closure, hãy chạy bước propagation chuỗi và cấu trúc trước và sau khi inline.<sup>[[1]](#references)</sup>

Ngoài ra, hãy nhận diện các closure gọi một hàm được lưu trữ đúng một lần, xóa tham chiếu đến hàm đó, cache kết quả rồi trả về cache trong các lần gọi sau. Gộp thunk như vậy tại vị trí khởi tạo sẽ làm lộ dispatcher hoặc capability function bên dưới, nhưng hãy ghi chú rằng quá trình thực thi ban đầu là **one-shot và được cache**, thay vì mô hình hóa mỗi lần gọi như một lần gọi mới.<sup>[[1]](#references)</sup>

## Ghi chú về an toàn và xác thực

- Việc load `pickle` bằng Python có thể thực thi code. Chỉ load các file `.pkl` được tạo cục bộ từ lần chạy View8 đáng tin cậy; tuyệt đối không coi pickle do mẫu cung cấp là dữ liệu.<sup>[[2]](#references)</sup>
- Thiếu phần thân hàm không chứng minh rằng source không có hàm đó: V8 có thể serialize một lazy function dưới dạng metadata cho đến khi hàm được biên dịch trong lần gọi đầu tiên. Hãy giữ các hàm như vậy ở trạng thái unresolved trong quá trình static triage.<sup>[[6]](#references)</sup>
- Các pass dựa trên pattern không phải là JavaScript decompiler tổng quát. Hãy giữ nguyên các biểu thức chưa giải quyết được và kiểm tra thủ công các biến thể dispatcher không rõ ràng thay vì ép viết lại.<sup>[[1]](#references)[[2]](#references)</sup>
- Tên hàm được gợi ý bằng LLM chỉ là gợi ý điều hướng, không phải bằng chứng. Nếu sử dụng chúng, hãy xử lý dependency theo thứ tự leaf-first, nhưng xác minh từng nhãn dựa trên phần thân hàm, đối số, chuỗi, luồng dữ liệu, API và side effect.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Phá vỡ lớp bảo vệ: Deobfuscation tĩnh bytecode V8 đã biên dịch của JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Header V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Code cache của Node.js vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
