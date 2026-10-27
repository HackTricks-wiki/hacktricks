# Giả mạo Call Stack trên ARM64/ARM64e

{{#include ../../../banners/hacktricks-training.md}}

## Vì sao có thể giả mạo quá trình unwind dựa trên metadata

Một số công cụ bảo mật trên macOS ủy quyền việc thu thập thread stack cho `/usr/sbin/spindump` hoặc tin cậy một unwinder thông thường dựa trên metadata. Implant có thể khai thác ranh giới tin cậy đó bằng cách đặt các bản ghi tổng hợp đúng ABI trên stack, khiến một API nhạy cảm có vẻ như được gọi qua các hàm do kẻ tấn công chọn trong dyld và các framework của Apple đã được tải, thay vì từ mã implant không có bản sao lưu. Đây là hành vi đánh lừa telemetry, không phải thay đổi executable hay metadata unwind của nó.<sup>[[1]](#references)</sup>

Xem [macOS stackshots and `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) để biết bối cảnh phía thu thập.

Unwinder không xác minh rằng một prologue do compiler tạo ra đã tạo bản ghi. Nó liên tục dùng `PC` hiện tại để chọn một recipe Mach-O, áp dụng recipe đó cho `SP`, `x29`, `x30`, bộ nhớ stack và mọi thanh ghi nonvolatile được khai báo, rồi dùng `PC` của caller được khôi phục để chọn recipe tiếp theo. Nếu bộ nhớ do kẻ tấn công kiểm soát đáp ứng mọi recipe được chọn, chuỗi kết quả có thể hợp lệ về cấu trúc và ánh xạ được sang symbol, dù các lời gọi đó chưa từng xảy ra.<sup>[[1]](#references)</sup>

## Trạng thái frame ARM64

[Tổng quan về assembly ARM64](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) trình bày vai trò của các thanh ghi và calling convention. Với một frame thông thường được tạo bằng `stp x29, x30, [sp, #-16]!` rồi đến `mov x29, sp`, Canonical Frame Address (CFA), biểu thị `SP` tại thời điểm caller bắt đầu thực thi, là `FP+0x10`:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Các frame record tạo thành một linked list thông qua `[FP]`, nhưng chỉ lần theo danh sách đó là chưa đủ: các hàm lá có thể không có frame, tail call có thể loại bỏ các chuyển tiếp logic, và các layout bất thường sử dụng DWARF CFI. Recipe được chọn theo địa chỉ hiện tại sẽ quyết định unwinder có đọc chuỗi FP hay không.<sup>[[1]](#references)[[4]](#references)</sup>

## Chọn recipe unwind của Mach-O

Các image đã được link cuối cùng lưu dữ liệu compact unwind trong `__TEXT,__unwind_info`. Header của section trỏ đến function index cấp một; mỗi phạm vi index trỏ đến một trang cấp hai dạng thường (`kind=2`) hoặc nén (`kind=3`). Các layout mà compact unwind không thể mô tả sẽ dùng FDE và call-frame instructions trong `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

Với mỗi PC runtime cần kiểm tra:<sup>[[1]](#references)[[2]](#references)</sup>

1. Chỉ loại bỏ hoặc chuẩn hóa các bit PAC của ARM64e để tra cứu.
2. Tìm Mach-O đã load có phạm vi `__TEXT` thực thi chứa địa chỉ đó.
3. Tính `functionOffset = normalizedPC - loadedImageBase` và từ chối kết quả âm hoặc lớn hơn `UINT32_MAX`.
4. Chọn phạm vi cấp một đầu tiên thỏa mãn `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`.
5. Phân tích trang cấp hai được tham chiếu, chọn entry gần nhất có giá trị bắt đầu không vượt quá offset, rồi xác minh địa chỉ nằm dưới entry kế tiếp hoặc cuối phạm vi cấp một.
6. Giải mã entry đó và dựng chính xác trạng thái mà nó mô tả.

Nếu địa chỉ lấy từ LR đã lưu, có thể tra cứu bằng `PC-1` để địa chỉ ngay sau một lệnh gọi vẫn nằm trong phạm vi được bao phủ của caller. Thao tác này chỉ thay đổi việc chọn recipe, không thay đổi bất kỳ stack offset nào.<sup>[[1]](#references)</sup>

Parser phải kiểm tra giới hạn của mọi header và array, yêu cầu section version là `1`, tính đến sentinel cấp một cuối cùng, từ chối offset trang cấp hai bằng 0 và phân biệt trang thường với trang nén. Trong trang thường, `entryPageOffset` được tính tương đối so với đầu trang đó, trong khi offset trang cấp một được tính tương đối so với đầu `__unwind_info`.<sup>[[1]](#references)[[2]](#references)</sup>

Mode tổng quát được xác định bởi `encoding & 0x0F000000`. Các định nghĩa LLVM hiện tại bao gồm những mode sau; parser không nên xem mọi giá trị không phải DWARF là frame kiểu cổ điển:<sup>[[1]](#references)[[2]](#references)</sup>

| Mode | Value | Khôi phục caller |
| --- | --- | --- |
| Không có compact recipe | `0x00000000` | Dừng hoặc dùng fallback độc lập. |
| Frameless | `0x02000000` | Cộng stack size đã mã hóa vào `SP` hiện tại; PC của caller là LR đang hoạt động. |
| DWARF | `0x03000000` | Thực thi FDE/CFI được xác định bởi 24 bit thấp. |
| Frame | `0x04000000` | Đọc frame record `x29` theo quy ước. |
| Frame arm64e có phạm vi LR được xác thực | `0x05000000` | Xử lý `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`; trường offset xác định vị trí `pacibsppc` trong phạm vi được bao phủ. |

Với mode frameless, `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. Với mode frame, năm bit thấp khai báo các cặp GPR được lưu liên tiếp từ `x19/x20` đến `x27/x28`; các bit `0x100-0x800` cũng khai báo tương tự cho các cặp `d8-d15`. Có thể không cần các register đã lưu đó để tìm PC tiếp theo, nhưng trạng thái caller ảo đáng tin cậy phải đáp ứng mọi trường mà consumer khôi phục.<sup>[[1]](#references)[[2]](#references)</sup>

## Dựng các frame-mode record tổng hợp

Quy trình dựng đảo ngược hoạt động của unwinder, thay vì quét stack để tìm các giá trị trông giống địa chỉ:<sup>[[1]](#references)</sup>

1. Chọn một PC thực thi hợp lệ trong image hiện được load.
2. Giải mã recipe bao phủ chính xác PC hoặc địa chỉ call-site đó.
3. Cấp phát một record tổng hợp với alignment và quan hệ CFA phù hợp.
4. Lưu FP tổng hợp tiếp theo tại `[FP]`, PC caller đã lưu của frame đó tại `[FP+8]`, và mọi GPR/FPR được encoding khai báo là lưu dưới FP.
5. Liên kết nhiều record và đặt record đầu tiên vào `x29` đang hoạt động.
6. Sắp xếp LR đang hoạt động và đường đi trả về của API để quá trình unwind đi vào chain đã chọn, đồng thời vẫn có thể khôi phục an toàn trạng thái thực thi.

Ví dụ, `0x04000001` có nghĩa là mode frame cộng với cặp `x19/x20`. Phép biến đổi trạng thái tương ứng và bộ nhớ cần thiết là:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

Do đó, một địa chỉ trông hợp lệ là chưa đủ. Mỗi PC được khôi phục sẽ trở thành khóa cho lần tra cứu tiếp theo, vì vậy chỉ cần một địa chỉ có cách mã hóa không khớp với bố cục giả lập là chuỗi bị đứt hoặc khiến bên tiêu thụ tái dựng trạng thái thanh ghi không nhất quán.<sup>[[1]](#references)</sup>

## Yêu cầu PAC của ARM64e

PAC lưu trữ một giá trị toàn vẹn có khóa trong các bit con trỏ vốn không được sử dụng; nó không mã hóa địa chỉ. Lược đồ địa chỉ trả về arm64e của Clang sử dụng khóa lệnh B và stack pointer tại thời điểm vào hàm làm giá trị phân biệt. Với một frame thông thường, `SP` tại thời điểm vào hàm là CFA, do đó LR đã lưu tại `[FP+8]` được ràng buộc với `FP+0x10`.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Mỗi LR tổng hợp phải được ký độc lập vì chuyển một LR đã ký sang frame có CFA khác sẽ làm thay đổi discriminator và khiến quá trình xác thực thất bại. `ptrauth_strip()` phù hợp để chuẩn hóa địa chỉ và tra cứu symbol nhưng **không** chứng minh tính xác thực; mọi lệnh return thực sự hoặc nhánh gián tiếp có xác thực đều phải dùng key và modifier được mong đợi tại đúng thời điểm chuyển tiếp đó.<sup>[[1]](#references)[[3]](#references)</sup>

Một hàm arm64e không phải leaf thường ký LR trước khi lưu và xác thực sau khi khôi phục SP lúc vào hàm:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline và restore bridge

Các bản ghi tổng hợp chỉ cần đáp ứng yêu cầu của unwinder; chúng không chứa đầy đủ execution context. Việc quay về từ API nhạy cảm trực tiếp vào các caller giả lập thường sẽ gây crash. Vì vậy, thiết kế thực tế đặt một gadget frame ngay bên dưới API: API quay về đoạn mã thực thi trong một framework đã được nạp, còn gadget đó nhảy qua một thanh ghi callee-saved được kiểm soát đến restore bridge trong implant.<sup>[[1]](#references)</sup>

Một gadget hữu ích sẽ giữ nguyên LR và chuyển luồng qua một thanh ghi được kiểm soát, chẳng hạn chuỗi lệnh `br`, `braa` hoặc `brab` phù hợp. Restore bridge phải khôi phục các giá trị `x19-x30` ban đầu và `SP` trước khi tiếp tục thực thi implant. Trên arm64e, mỗi lệnh return hoặc branch có xác thực trong đường đi từ API đến gadget, gadget đến bridge và bridge đến implant đều cần một pointer được ký bằng key và discriminator mà lệnh đó sử dụng.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

Kết quả này cho thấy một lỗi ranh giới tin cậy nghiêm trọng đối với các phương pháp phát hiện dựa trên stack: một chain có thể chỉ chứa các PC đã được map và có thể symbolicate thuộc framework của Apple nhưng vẫn không phản ánh luồng điều khiển thực tế. Vì vậy, cần đối chiếu kết quả unwind với bằng chứng độc lập về nguồn gốc bộ nhớ executable của thread và các chuyển tiếp thực tế xung quanh API nhạy cảm, thay vì xem đó là execution trace.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Nội bộ stack ARM64 và kỹ thuật obfuscation trên Apple Silicon](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Định nghĩa mã hóa compact unwind của Mach-O](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Pointer Authentication](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Chuẩn gọi thủ tục cho kiến trúc Arm 64-bit](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
