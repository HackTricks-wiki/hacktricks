# Deobfuscation tĩnh của bytecode cache Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Dữ liệu cache của V8 là **biểu diễn phụ thuộc phiên bản và bị mất thông tin**, không phải mã nguồn JavaScript hay tệp thực thi native thông thường. Vì vậy, quy trình tĩnh hữu ích là: gỡ bỏ mọi lớp đóng gói bên ngoài, disassemble cache bằng bản dựng V8 tương ứng, chuyển đổi nó thành mô hình pseudocode trung gian và áp dụng các phép biến đổi có xét đến quan hệ phụ thuộc mà không thực thi mẫu. [View8](https://github.com/suleram/View8) và [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) triển khai phương pháp này cho các payload Node.js được bảo vệ bằng `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Thu thập và disassemble cache

Trước tiên, hãy kiểm tra preload/launcher thay vì giả định rằng mọi tệp `.jsc` đều có cùng wrapper. Ví dụ, launcher như `node.exe -r preflight.js app.jsc` thực thi `preflight.js` trước module chính; trong họ mẫu được phân tích, preload đã gỡ bỏ một lớp Brotli. Sau khi giải nén, hãy xác định thế hệ Node.js/V8 chính xác từ runtime đi kèm. Cache được tạo bởi một phiên bản V8 có thể bị phiên bản khác từ chối hoặc giải mã không chính xác, vì vậy hãy xây dựng hoặc lấy `v8dasm` dành cho đúng thẻ V8 đó và áp dụng các bản vá View8 cùng bản vá in chuỗi cần thiết.<sup>[[1]](#references)[[2]](#references)</sup>

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

`--normalize` cung cấp cho các hàm được tạo mã định danh ổn định qua các lần chạy. Nội dung văn bản dùng để kiểm tra; đồ thị đối tượng được tuần tự hóa cho phép các lượt xử lý độc lập giữ nguyên mối quan hệ giữa hàm, hàm khai báo, scope và metadata. Đây **không phải JavaScript được tái dựng hay có thể chạy**.<sup>[[1]](#references)[[2]](#references)</sup>

### Phân tích cache ban đầu mà không cần build V8

Với cache thô hoặc được bọc bằng Brotli, `jscd` có thể nhận diện header và liệt kê các constant cùng function mà không cần tải mẫu vào Node.js. Trước tiên, hãy dùng công cụ này để kiểm tra xem các bảng phiên bản có hỗ trợ tệp hay không và ưu tiên function trước khi chạy các lượt xử lý deobfuscation chuyên biệt hơn của View8.<sup>[[4]](#references)</sup>

Version hash là gợi ý nhận diện, không phải bằng chứng cho thấy một disassembler độc lập có cùng flags hoặc read-only snapshot như bên tạo ra nó.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` xuất ra listing tương thích với View8, vì vậy lệnh View8 ở trên có thể dùng đầu ra đó thay cho `v8dasm` khi cache được hỗ trợ. Kiểm tra các chuỗi cùng với cây hàm để tìm các lệnh gọi decoder và những entry point có khả năng là điểm bắt đầu; đừng xem đầu ra JavaScript gần đúng của `jscd` là mã nguồn gốc. Nếu công cụ từ chối phiên bản hoặc để lại các placeholder của read-only-heap, hãy dùng lại bản dựng V8 tương ứng hoặc cung cấp name map từ cùng bản dựng thay vì đoán tên thuộc tính.<sup>[[4]](#references)</sup>

Với cache bên trong ứng dụng Electron, trước tiên hãy [trích xuất ASAR và kiểm tra các entry point main và preload](../../network-services-pentesting/pentesting-web/electron-desktop-apps/). Bố cục snapshot và pointer-compression trong cache của Electron và Node có thể khác nhau ngay cả khi chuỗi phiên bản V8 trùng khớp.<sup>[[4]](#references)</sup>

### Đọc pseudocode View8 dưới dạng IR

Tên thường có dạng `func_<name>_0x<address>`, các đối số là `a0...aN`, thanh ghi ảo là `r0...rN`, còn `ACCU` là accumulator của V8. `start` là declarer gốc, trong khi `Scope[...]`, biến toàn cục và dictionary mô hình hóa các giá trị được capture hoặc chia sẻ bởi các hàm lồng nhau. Đừng phân tích mọi biểu thức theo cú pháp JavaScript: chẳng hạn, `!r6 === "0"` trong View8 biểu thị phép phủ định của toàn bộ phép so sánh (`r6 !== "0"`), điều này rất quan trọng khi dựng lại các nhánh.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuscation có xét đến phụ thuộc

Áp dụng các phép biến đổi theo thứ tự làm lộ ra đầu vào cần thiết cho lượt xử lý tiếp theo, rồi lặp lại việc lan truyền cho đến khi đầu ra ổn định. Thứ tự thực tế là:<sup>[[1]](#references)[[2]](#references)</sup>

1. Duyệt phân cấp declarer và lan truyền giá trị từ biến toàn cục, thanh ghi, dictionary và tham chiếu `Scope[...]`.
2. Khôi phục đối số của string-decoder và thay các lời gọi đã mã hóa bằng văn bản thuần.
3. Ghép các đoạn chuỗi liền kề; tên thuộc tính và chuỗi thứ tự dispatcher thu được sẽ mở khóa các lượt xử lý sau.
4. Gỡ flatten luồng điều khiển, inline call proxy và wrapper của atomic operation, đồng thời phân giải các tham chiếu hàm được lưu trong dictionary.
5. Lan truyền lại vì mỗi chuỗi, key hoặc proxy đã phân giải có thể làm lộ thêm một lớp chuyển hướng.
6. Chỉ rút gọn các thunk khởi tạo một lần đã nhận diện và loại bỏ helper không còn được dùng sau khi đã phân giải các call site của chúng.

### Khôi phục các mảng chuỗi RC4 bị dịch chuyển dưới dạng black box

Một bố cục `javascript-obfuscator` phổ biến lưu các chunk RC4 đã mã hóa Base64 trong một mảng. Các wrapper decoder cung cấp độ lệch dạng số và một key ngắn, đôi khi đảo thứ tự đối số, rồi cộng hoặc trừ các hằng số được capture trong scope closure. Khi decoder gốc bị obfuscate quá nặng, hãy tìm thực nghiệm độ dịch chuyển chỉ số mảng chưa biết thay vì dựng lại toàn bộ hàm.<sup>[[1]](#references)</sup>

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

Không chấp nhận một phép dịch chỉ vì kết quả giải mã duy nhất trông như văn bản có thể in được: ciphertext sai vẫn có thể tình cờ cho ra kết quả như vậy. Hãy dùng ít nhất ba quan sát riêng biệt và chỉ chấp nhận một phép dịch duy nhất tạo ra văn bản hợp lý trong tất cả các quan sát. Sau đó, duyệt đồ thị wrapper/declarer, cộng dồn mỗi phép cộng hoặc trừ và ghi lại liệu đối số số học đứng trước hay không. Cache metadata này cho từng sample, thay thế các lời gọi decoder, nối các đoạn plaintext liền kề và xuất riêng các chuỗi để triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Bảo toàn ngữ nghĩa khi unflatten

Với các vòng lặp dispatcher được điều khiển bằng chuỗi như `3|2|1|0|4`, hãy giải mã chuỗi thứ tự, ánh xạ từng phép so sánh trạng thái với block tương ứng, xử lý ký hiệu điều kiện phủ định của View8, rồi xuất các block theo thứ tự dispatcher. Một `continue` lồng bên trong có thể biểu thị một bước nhảy sớm trở lại dispatcher, chứ không phải luồng chạy tiếp thông thường. Khi xóa vòng lặp, hãy xóa `continue` đó và chuyển các câu lệnh vốn nằm sau `if` bao quanh nó vào một nhánh `else` được tạo ra; chỉ xóa dispatcher sẽ làm thay đổi hành vi.<sup>[[1]](#references)</sup>

### Inline proxy, phép toán và thunk lazy

Chuẩn hóa các helper chuyển tiếp như `return a0(a1, a2)` trước khi thay các call site bằng lời gọi trực tiếp. Xử lý tương tự các wrapper cho phép trừ, phép chia, phép so sánh, phép kiểm tra membership hoặc lời gọi hàm. Vì tham chiếu helper có thể được lưu phía sau một khóa dictionary đã giải mã hoặc một giá trị closure, hãy chạy quá trình lan truyền chuỗi và cấu trúc trước và sau khi inline.<sup>[[1]](#references)</sup>

Ngoài ra, hãy nhận diện các closure gọi một hàm được lưu trữ đúng một lần, xóa tham chiếu đến hàm đó, cache kết quả rồi trả về cache trong các lần gọi sau. Gộp thunk như vậy tại điểm khởi tạo sẽ làm lộ dispatcher hoặc hàm capability bên dưới, nhưng cần chú thích rằng khi chạy ban đầu, hàm này **chỉ chạy một lần và được cache**, thay vì mô hình hóa mỗi lần gọi như một lần thực thi mới.<sup>[[1]](#references)</sup>

## Ghi chú về an toàn và xác thực

- Việc tải Python `pickle` có thể thực thi code. Chỉ tải các file `.pkl` được tạo cục bộ bởi lần chạy View8 đáng tin cậy; tuyệt đối không xem pickle do sample cung cấp là dữ liệu.<sup>[[2]](#references)</sup>
- Việc thiếu thân hàm không chứng minh rằng source không có hàm đó: V8 có thể serialize một hàm lazy dưới dạng metadata cho đến khi hàm được compile khi gọi lần đầu. Trong quá trình triage tĩnh, hãy giữ các hàm như vậy ở trạng thái chưa phân giải.<sup>[[6]](#references)</sup>
- Các pass dựa trên pattern không phải là trình decompiler JavaScript tổng quát. Hãy giữ nguyên các biểu thức chưa phân giải và kiểm tra thủ công những biến thể dispatcher chưa rõ ràng, thay vì ép buộc viết lại.<sup>[[1]](#references)[[2]](#references)</sup>
- Tên hàm do LLM hỗ trợ chỉ là gợi ý để điều hướng, không phải bằng chứng. Nếu sử dụng chúng, hãy xử lý dependency theo thứ tự từ lá lên trước, nhưng cần xác minh từng nhãn dựa trên thân hàm, đối số, chuỗi, luồng dữ liệu, API và side effect.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Phá vỡ lớp bảo vệ: Deobfuscation tĩnh bytecode V8 đã compile của JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Header SerializedCodeData của V8](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Cache mã vm.Script của Node.js](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
