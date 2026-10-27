# Thực thi payload được ảo hóa và né tránh VM tùy chỉnh

{{#include ../banners/hacktricks-training.md}}

Payload virtualization biên dịch logic tấn công thành tập lệnh của guest rồi thực thi bằng một trình thông dịch native. Khác với packer, vốn cuối cùng phải để lộ các lệnh native ban đầu trong bộ nhớ, payload được ảo hóa có thể giữ logic được bảo vệ dưới dạng bytecode trong suốt vòng đời của nó. Cách này loại bỏ khoảng thời gian giải nén cụ thể đó, nhưng **không** che giấu hành vi mà host có thể quan sát, chẳng hạn như syscall, hoạt động mạng hoặc ranh giới gọi từ VM sang native.<sup>[[2]](#references)[[3]](#references)</sup>

## Re-hosting WebAssembly để né tránh phân tích tĩnh

Thay vì chỉnh sửa một công cụ Go có nhiều signature, có thể biên dịch công cụ đó thành guest `wasip1` rồi nhúng vào một loader native riêng. Guest được xây dựng dựa trên GOROOT đã vá, trong đó các thao tác không được hỗ trợ như `net.Dial`, `net.Listen`, `os/exec` và `os.Pipe` chuyển tiếp qua `//go:wasmimport`; sau đó, một host module Wazero triển khai socket, thao tác tiến trình, lệnh gọi Win32 và lệnh gọi framework macOS. Cách này giữ nguyên việc sử dụng Go API của dự án gốc, đồng thời chuyển phần lớn logic vào một module WASM được mã hóa mà các công cụ PE tĩnh có thể không hiểu được.<sup>[[4]](#references)</sup>

### Kết nối linear memory với native API

Con trỏ guest là một offset 32-bit trong WASM linear memory, không phải địa chỉ ảo của host. Trước một lệnh gọi native, bridge chỉ có thể chuyển đổi một đối số khi đối số đó được đánh dấu là con trỏ cục bộ và nằm trong phạm vi `0x10000 <= value < wasmMemorySize`, tạo ra `wasmMemoryBase + value`. Giới hạn dưới giúp tránh ghi đè các handle nhỏ, flag và `nil`; các mask theo từng API được tạo từ `win32metadata` dùng để phân biệt con trỏ thực với handle, kích thước và địa chỉ tiến trình từ xa, kèm các ngoại lệ cho metadata không chính xác hoặc không rõ ràng.<sup>[[4]](#references)</sup>

Native API cũng có thể trả về con trỏ host thông qua các buffer đầu ra của guest. Bảng mirror có thể gán biểu diễn trong guest memory cho các đối tượng đó và giữ ánh xạ ngược đến địa chỉ host ban đầu. COM yêu cầu mirror cả interface lẫn vtable: có thể lần theo và mirror các con trỏ dữ liệu, nhưng các con trỏ thực thi trong vùng `MEM_IMAGE` phải được giữ dưới dạng token opaque vì WASM không thể thực thi lệnh native. Mô hình này không hỗ trợ trực tiếp các API callback từ host sang guest như `EnumWindows` hoặc `SetWindowsHookEx`.<sup>[[4]](#references)</sup>

### Tính đa hình của WASM VM theo từng build

Runtime và payload có thể được biến đổi cùng nhau ở mỗi build: xáo trộn bảng ánh xạ opcode sang handler, viết lại mọi opcode guest theo ánh xạ mới, ngẫu nhiên hóa định danh section, thay magic chuẩn `\0asm` bằng marker riêng cho từng build và thay đổi magic của runtime cache. Cùng một source sẽ tạo ra các module khác nhau từng byte, còn các công cụ WASM thông thường không thể phân tích payload cho đến khi nhà phân tích khôi phục ánh xạ và framing tùy chỉnh từ host loader.<sup>[[4]](#references)</sup>

Để reverse engineering, hãy bắt đầu từ native host thay vì chỉ tìm dữ liệu theo `\0asm`: xác định marker đã biên dịch, luồng giải mã module, bảng dispatch opcode và các đăng ký host-function `env`, sau đó tái dựng một module chuẩn hoặc instrument ranh giới import. Bridge vẫn là một điểm kiểm soát hành vi hữu ích vì các lệnh gọi mạng, tạo tiến trình, truy cập registry, nạp động và dispatch Win32 tổng quát đều đi qua nó, ngay cả khi bytecode nhúng thay đổi giữa các build.<sup>[[4]](#references)</sup>

### Ngụy trang tệp thực thi Go bên ngoài

Chỉ thay đổi guest vẫn để lại một loader dễ nhận biết. Các phép biến đổi binary bên ngoài đã được trình diễn gồm ghép các profile symbol dày đặc thu thập từ những dự án Go hợp pháp vào `gopclntab`, xoay vòng một tập nhỏ các DLL import hợp lý, và thay đổi `VERSIONINFO` của PE cùng các chuỗi nhận dạng Authenticode. Những phép biến đổi này nhắm vào các đặc trưng tĩnh và machine-learning của container; chúng không loại bỏ hành vi runtime do các host shim để lộ.<sup>[[4]](#references)</sup>

## Mô hình thực thi

Một loader được ảo hóa gọn nhẹ có thể chia quá trình thực thi thành các lớp sau.<sup>[[3]](#references)</sup>

1. Biên dịch C freestanding, mã nguồn BOF hoặc runtime library qua LLVM thành một custom bytecode ISA.
2. Khởi chạy một native interpreter nhỏ và khởi tạo ánh xạ opcode riêng cho từng build.
3. Chạy chính PE linker-loader dưới dạng bytecode: phân tích header, ánh xạ section, áp dụng relocation, phân giải import và điền IAT.
4. Giữ các lệnh gọi từ guest đến guest bên trong interpreter. Chuyển các đích nằm ngoài vùng bytecode, chẳng hạn hàm DLL được import, qua một native host-call thunk.
5. Đưa các thành phần hỗ trợ như HTTP framing, TLS và một phần C runtime qua cùng ranh giới diễn giải.

Mô hình này tránh cấp phát một vùng mã native riêng cho từng plugin và ngăn payload gốc xuất hiện dưới dạng một luồng lệnh x86-64 dễ nhận diện. Đây vẫn là ranh giới né tránh/làm rối, không phải ranh giới bảo mật: native interpreter và mọi tác động bên ngoài đều có thể bị quan sát.<sup>[[2]](#references)[[3]](#references)</sup>

## Host bridge dùng chung bộ nhớ

VM cô lập biểu diễn con trỏ dưới dạng offset trong guest buffer, vì vậy mỗi lần gọi API qua host đều cần chuyển đổi con trỏ và xử lý đặc biệt các tham số đầu ra. VM dùng chung bộ nhớ thay vào đó khiến địa chỉ guest trở thành địa chỉ hợp lệ trong tiến trình host. Do đó, thao tác đọc và ghi có thể dùng kiểu `memcpy`, còn con trỏ do native allocation ECALL trả về có thể được bytecode dereference trực tiếp. RISC-Y Business đã chứng minh rằng thiết kế này có thể rút gọn bridge xuống còn việc lấy PEB và thực hiện các lệnh gọi host tùy ý.<sup>[[1]](#references)</sup>

Trên Windows x64, virtual register file có thể phản chiếu ABI: đặt bốn đối số integer hoặc con trỏ đầu tiên vào `RCX`, `RDX`, `R8` và `R9`, các đối số tiếp theo cùng shadow space nằm trên stack. Khi một lệnh `CALL` ảo phân giải đến địa chỉ ngoài vùng bytecode, universal thunk sẽ marshal trạng thái đó thành lệnh gọi native rồi sao chép giá trị trả về về VM. Điều này cho phép gọi IAT, cấp phát heap và thực hiện thao tác socket mà không cần hiệu chỉnh con trỏ.<sup>[[2]](#references)[[3]](#references)</sup>

Đổi lại, thiết kế này mất hoàn toàn tính cô lập. Lỗi bộ nhớ trong guest có thể ảnh hưởng trực tiếp đến host, native callee có thể giữ lại hoặc sửa đổi con trỏ guest, và interpreter phải xem bytecode là hoàn toàn đáng tin cậy. Callback từ native sang VM cũng cần một bridge ngược; VM chỉ hỗ trợ gọi ra ngoài không thể trực tiếp đáp ứng các API dựa trên callback như `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Tính đa hình ISA theo từng build

Custom ISA có độ rộng cố định giúp đơn giản hóa việc giải mã, dispatch, relocation và ánh xạ virtual register. Centurion sử dụng định dạng lệnh 18 byte lấy cảm hứng từ x86-64, đánh đổi độ gọn của mã để có thể phân tích cú pháp dễ dự đoán, đồng thời mở ra khả năng chuyển các artifact x86-64 hiện có thành bytecode.<sup>[[3]](#references)</sup>

Ngẫu nhiên hóa ánh xạ opcode sang handler cho mỗi build khiến cùng một logic guest tạo ra các chuỗi byte khác nhau. Mã hóa bảng ánh xạ và chỉ khôi phục nó khi runtime càng loại bỏ thêm một từ điển opcode ổn định trên đĩa. Cách này gây khó khăn cho signature cố định và quy tắc disassembly có thể tái sử dụng, nhưng tự nó không làm đa hình native dispatcher, routine giải mã bảng hoặc ranh giới host-call.<sup>[[3]](#references)</sup>

## Đưa môi trường thực thi vào VM

Có thể thu gọn host process thành các primitive bộ nhớ, syscall và socket, trong khi các thư viện freestanding cung cấp dịch vụ cấp cao hơn bên trong VM. Ví dụ, FreeRTOS coreHTTP có thể xử lý HTTP framing và mbedTLS có thể xử lý TLS mà không cần gọi WinHTTP hoặc API TLS của hệ điều hành. Khi đó, raw socket qua `afd.sys` hoặc một interface tương tự trở thành ranh giới mạng native hẹp nhất.<sup>[[3]](#references)</sup>

Thiết kế **Bring Your Own Execution Environment (BYOEE)** này cũng có thể đặt PE loading, runtime support và filesystem trong bộ nhớ sau interpreter. Nó giảm số lượng triển khai native dễ nhận biết thay vì loại bỏ telemetry: thao tác raw socket vẫn hiển thị, và các môi trường yêu cầu proxy tường minh hoặc TLS interception có thể khiến thiết kế mạng không hoạt động.<sup>[[3]](#references)</sup>

## Tăng tốc native có chọn lọc

Diễn giải mọi lệnh đặc biệt tốn kém trong mật mã khóa công khai. Một cách phân chia thực tế là dùng các hook `MBEDTLS_ALT` của mbedTLS như một giao diện software-coprocessor: giữ trạng thái TLS, phân tích chứng chỉ, thương lượng, cấp phát và mã bignum cấp cao trong bytecode, nhưng dispatch các kernel số học nóng trong `bignum_core.c` qua native ECALL. Trong prototype Centurion, `bignum.c`, `bignum_mod.c` và `bignum_mod_raw.c` vẫn được ảo hóa, còn các vòng lặp bên trong chạy native, giúp giảm thời gian bắt tay ECDHE từ vài phút xuống còn vài giây.<sup>[[3]](#references)</sup>

Hãy để tùy chọn tăng tốc ở trạng thái có thể bật/tắt để payload không cần TLS có thể bỏ các native entry point bổ sung. Mẫu này áp dụng được cho mọi workload của interpreter: trước tiên hãy profiling, sau đó chỉ đưa primitive native nhỏ nhất có thể ra ngoài, thay vì chuyển cả subsystem ra khỏi VM.<sup>[[3]](#references)</sup>

Centurion đã kiểm chứng toàn bộ chuỗi bằng một bind shell TLS 1.2: bytecode loader ánh xạ PE, các lệnh gọi socket đi qua universal thunk, mbedTLS xử lý giao thức bên trong VM, còn native ECALL tăng tốc phép toán ECDHE. Nhờ đó, native interpreter có kích thước khoảng 18 KB hỗ trợ một kênh lệnh được mã hóa mà không tạo payload thành mã x86-64 native trong bộ nhớ.<sup>[[3]](#references)</sup>

## Điểm neo cho reverse engineering và phát hiện

Dưới đây là các điểm neo phân tích thực tế suy ra từ kiến trúc; virtualization thay đổi vị trí nhà phân tích quan sát hành vi, nhưng không loại bỏ chính hành vi đó.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Xác định vòng lặp fetch/decode/dispatch, virtual program counter, register file và bước tiến lặp lại theo lệnh có độ rộng cố định.
- Dump bảng opcode sau khi giải mã runtime rồi ánh xạ địa chỉ handler về các thao tác ngữ nghĩa, thay vì đối chiếu bytecode đã mã hóa trên đĩa.
- Đặt breakpoint tại universal thunk hoặc ECALL dispatcher để ghi lại đích native, virtual argument register, stack argument và giá trị trả về.
- Theo dõi truy cập PEB, phân giải export, phân tích PE header, ghi relocation và điền IAT, ngay cả khi chính phần triển khai loader là bytecode.
- Đối chiếu việc tạo socket và lưu lượng `afd.sys` với sự vắng mặt của các lệnh gọi WinHTTP hoặc TLS native dự kiến; thiếu các high-level import là một manh mối, không phải bằng chứng về hành vi vô hại.
- Xem native arithmetic accelerator là các điểm kiểm soát ngữ nghĩa: caller của chúng có thể tiết lộ hoạt động trao đổi khóa và xác thực chứng chỉ trong khi state machine TLS xung quanh vẫn được ảo hóa.

Để xem quy trình phân tích bắt đầu từ dispatcher thay vì control-flow graph gốc, hãy tham khảo [malware-analysis guidance for virtualizing packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Ràng buộc vận hành

Virtualization tạo thêm chi phí diễn giải, làm tăng độ phức tạp của toolchain và ABI, đồng thời không giải quyết được vấn đề phát hiện hành vi. Shared memory vốn không an toàn, mạng raw-socket có thể không hoạt động phía sau proxy bắt buộc, còn các Win32 API dùng nhiều callback cần trampoline từ native sang VM. Interpreter, syscall bridge và mọi native accelerator cũng vẫn tạo ra dấu vết native thông thường mà bên phòng thủ có thể tạo signature hoặc instrument.<sup>[[2]](#references)[[3]](#references)</sup>

## Các trang liên quan

Để phân tích việc đóng gói VMProtect 3.x, xem [emulated unpacking and import repair](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair).

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Xây dựng máy ảo RISC-V để làm rối payload](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red Teaming trong kỷ nguyên EDR — Né tránh bằng cách ảo hóa malware](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Tự mang theo môi trường thực thi](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - Bước vào WasmForge: Biên dịch Sliver sang WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
