# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) là một chương trình hữu ích để tìm vị trí lưu các giá trị quan trọng trong bộ nhớ của game đang chạy và thay đổi chúng.\
Khi tải xuống và chạy chương trình, bạn sẽ được **giới thiệu** một **hướng dẫn** cách sử dụng công cụ. Nếu muốn học cách sử dụng, bạn nên hoàn thành hướng dẫn này.

## Bạn đang tìm gì?

![Cheat Engine - Bạn đang tìm gì?: Bạn đang tìm gì?](<../../images/image (762).png>)

Công cụ này rất hữu ích để tìm **vị trí một giá trị nào đó** (thường là một con số) **được lưu trong bộ nhớ** của chương trình.\
**Các con số** thường được lưu dưới dạng **4bytes**, nhưng bạn cũng có thể tìm chúng ở định dạng **double** hoặc **float**, hoặc có thể muốn tìm thứ gì đó **không phải là số**. Vì vậy, hãy đảm bảo bạn **chọn** đúng thứ muốn **tìm kiếm**:

![Cheat Engine - Bạn đang tìm gì?: Các con số thường được lưu dưới dạng 4bytes, nhưng bạn cũng có thể tìm chúng ở định dạng double hoặc float, hoặc có thể muốn tìm thứ gì đó...](<../../images/image (324).png>)

Bạn cũng có thể chọn **các kiểu tìm kiếm khác nhau**:

![Cheat Engine - Bạn đang tìm gì?: Bạn cũng có thể chọn các kiểu tìm kiếm khác nhau](<../../images/image (311).png>)

Bạn cũng có thể đánh dấu ô để **tạm dừng game trong khi quét bộ nhớ**:

![Cheat Engine - Bạn đang tìm gì?: Bạn cũng có thể đánh dấu ô để tạm dừng game trong khi quét bộ nhớ](<../../images/image (1052).png>)

### Phím nóng

Trong _**Edit --> Settings --> Hotkeys**_, bạn có thể thiết lập các **phím nóng** cho nhiều mục đích khác nhau, chẳng hạn như **tạm dừng** **game** (điều này khá hữu ích nếu có lúc bạn muốn quét bộ nhớ). Ngoài ra còn có các tùy chọn khác:

![Bạn đang tìm gì? - Phím nóng: Trong Edit -- Settings -- Hotkeys, bạn có thể thiết lập các phím nóng cho nhiều mục đích khác nhau, chẳng hạn như tạm dừng game (điều này khá hữu ích nếu có lúc bạn...](<../../images/image (864).png>)

## Thay đổi giá trị

Sau khi **tìm thấy** vị trí của **giá trị** cần **tìm** (sẽ nói thêm ở các bước sau), bạn có thể **thay đổi giá trị** bằng cách nhấp đúp vào nó, rồi nhấp đúp vào giá trị của nó:

![Phím nóng - Thay đổi giá trị: Sau khi tìm thấy vị trí của giá trị cần tìm (sẽ nói thêm ở các bước sau), bạn có thể thay đổi giá trị bằng cách nhấp đúp vào nó, rồi nhấp đúp...](<../../images/image (563).png>)

Cuối cùng, **đánh dấu vào ô** để áp dụng thay đổi trong bộ nhớ:

![Phím nóng - Thay đổi giá trị: Cuối cùng, đánh dấu vào ô để áp dụng thay đổi trong bộ nhớ](<../../images/image (385).png>)

Thay đổi trong **bộ nhớ** sẽ được **áp dụng** ngay lập tức (lưu ý rằng giá trị **sẽ không được cập nhật trong game** cho đến khi game sử dụng lại giá trị đó).

## Tìm kiếm giá trị

Giả sử có một giá trị quan trọng (chẳng hạn như máu của nhân vật) mà bạn muốn tăng, và bạn đang tìm giá trị này trong bộ nhớ.

### Dựa trên một thay đổi đã biết

Giả sử bạn đang tìm giá trị 100. Bạn **quét** để tìm giá trị đó và nhận được rất nhiều kết quả trùng khớp:

![Tìm kiếm giá trị - Dựa trên một thay đổi đã biết: Giả sử bạn đang tìm giá trị 100. Bạn quét để tìm giá trị đó và nhận được rất nhiều kết quả trùng khớp](<../../images/image (108).png>)

Sau đó, bạn làm gì đó để **thay đổi giá trị**, rồi **tạm dừng** game và **quét tiếp**:

![Tìm kiếm giá trị - Dựa trên một thay đổi đã biết: Sau đó, bạn làm gì đó để thay đổi giá trị, rồi tạm dừng game và quét tiếp](<../../images/image (684).png>)

Cheat Engine sẽ tìm các **giá trị** đã **thay đổi từ 100 sang giá trị mới**. Chúc mừng, bạn đã **tìm thấy địa chỉ** của giá trị cần tìm và giờ có thể thay đổi nó.\
_Nếu vẫn còn nhiều kết quả, hãy làm gì đó để thay đổi giá trị lần nữa, rồi thực hiện thêm một lần "next scan" để lọc các địa chỉ._

### Không biết giá trị, nhưng biết thay đổi

Nếu bạn **không biết giá trị** nhưng biết **cách làm nó thay đổi** (thậm chí biết mức thay đổi), bạn vẫn có thể tìm con số đó.

Trước tiên, hãy quét với kiểu "**Unknown initial value**":

![Dựa trên một thay đổi đã biết - Không biết giá trị, nhưng biết thay đổi: Trước tiên, hãy quét với kiểu "Unknown initial value"](../../images/image (890).png>)

Sau đó, làm cho giá trị thay đổi, cho biết giá trị đã thay đổi **như thế nào** (trong trường hợp của tôi, nó giảm 1) và thực hiện **quét tiếp**:

![Dựa trên một thay đổi đã biết - Không biết giá trị, nhưng biết thay đổi: Sau đó, làm cho giá trị thay đổi, cho biết giá trị đã thay đổi như thế nào (trong trường hợp của tôi, nó giảm 1) và thực hiện quét tiếp](<../../images/image (371).png>)

Bạn sẽ thấy **tất cả các giá trị đã thay đổi theo cách đã chọn**:

![Dựa trên một thay đổi đã biết - Không biết giá trị, nhưng biết thay đổi: Bạn sẽ thấy tất cả các giá trị đã thay đổi theo cách đã chọn](<../../images/image (569).png>)

Khi đã tìm thấy giá trị cần tìm, bạn có thể thay đổi nó.

Lưu ý rằng có **nhiều kiểu thay đổi** và bạn có thể thực hiện các **bước này bao nhiêu lần tùy ý** để lọc kết quả:

![Dựa trên một thay đổi đã biết - Không biết giá trị, nhưng biết thay đổi: Lưu ý rằng có nhiều kiểu thay đổi và bạn có thể thực hiện các bước này bao nhiêu lần tùy ý để lọc kết quả](<../../images/image (574).png>)

### Địa chỉ bộ nhớ ngẫu nhiên - Tìm code

Đến đây, chúng ta đã biết cách tìm địa chỉ lưu giá trị, nhưng có khả năng **địa chỉ đó sẽ nằm ở vị trí khác trong bộ nhớ mỗi lần chạy game**. Vì vậy, hãy tìm cách luôn xác định được địa chỉ đó.

Dùng một trong các thủ thuật đã nêu để tìm địa chỉ đang lưu giá trị quan trọng trong game hiện tại. Sau đó (có thể tạm dừng game nếu muốn), **nhấp chuột phải** vào **địa chỉ** vừa tìm được và chọn "**Find out what accesses this address**" hoặc "**Find out what writes to this address**":

![Không biết giá trị, nhưng biết thay đổi - Địa chỉ bộ nhớ ngẫu nhiên - Tìm code: Dùng một trong các thủ thuật đã nêu để tìm địa chỉ đang lưu giá trị quan trọng trong game hiện tại. Sau đó...](<../../images/image (1067).png>)

**Tùy chọn đầu tiên** giúp xác định những **phần** nào của **code** đang **sử dụng** **địa chỉ này** (điều này còn hữu ích cho nhiều việc khác, chẳng hạn như **biết vị trí có thể sửa code** của game).\
**Tùy chọn thứ hai** cụ thể hơn và hữu ích hơn trong trường hợp này, vì chúng ta muốn biết **giá trị này được ghi từ đâu**.

Sau khi chọn một trong hai tùy chọn, **debugger** sẽ được **gắn** vào chương trình và một **cửa sổ trống** mới sẽ xuất hiện. Giờ hãy **chơi game** và **thay đổi** **giá trị đó** (không khởi động lại game). **Cửa sổ** sẽ được **điền** các **địa chỉ** đang **thay đổi** **giá trị**:

![Không biết giá trị, nhưng biết thay đổi - Địa chỉ bộ nhớ ngẫu nhiên - Tìm code: Sau khi chọn một trong hai tùy chọn, debugger sẽ được gắn vào chương trình và một cửa sổ trống mới...](<../../images/image (91).png>)

Sau khi tìm thấy địa chỉ đang thay đổi giá trị, bạn có thể **tùy ý sửa code** (Cheat Engine cho phép bạn nhanh chóng thay bằng NOP):

![Không biết giá trị, nhưng biết thay đổi - Địa chỉ bộ nhớ ngẫu nhiên - Tìm code: Sau khi tìm thấy địa chỉ đang thay đổi giá trị, bạn có thể tùy ý sửa code (Cheat Engine...](<../../images/image (1057).png>)

Giờ bạn có thể sửa nó để code không tác động đến con số của mình, hoặc luôn tác động theo hướng có lợi.

### Địa chỉ bộ nhớ ngẫu nhiên - Tìm pointer

Làm theo các bước trước để tìm vị trí của giá trị bạn quan tâm. Sau đó, dùng "**Find out what writes to this address**" để tìm địa chỉ ghi giá trị này và nhấp đúp vào địa chỉ đó để mở chế độ xem disassembly:

![Địa chỉ bộ nhớ ngẫu nhiên - Tìm code - Địa chỉ bộ nhớ ngẫu nhiên - Tìm pointer: Làm theo các bước trước để tìm vị trí của giá trị bạn quan tâm. Sau đó, dùng "Find out...](<../../images/image (1039).png>)

Tiếp theo, thực hiện một lần quét mới để **tìm giá trị hex nằm giữa "\[]"** (trong trường hợp này là giá trị của $edx):

![Địa chỉ bộ nhớ ngẫu nhiên - Tìm code - Địa chỉ bộ nhớ ngẫu nhiên - Tìm pointer: Tiếp theo, thực hiện một lần quét mới để tìm giá trị hex nằm giữa " ()" (trong trường hợp này là giá trị của $edx)](<../../images/image (994).png>)

(_Nếu có nhiều kết quả, thường thì bạn cần địa chỉ nhỏ nhất_)\
Giờ chúng ta đã **tìm thấy pointer sẽ thay đổi giá trị cần quan tâm**.

Nhấp vào "**Add Address Manually**":

![Địa chỉ bộ nhớ ngẫu nhiên - Tìm code - Địa chỉ bộ nhớ ngẫu nhiên - Tìm pointer: Nhấp vào "Add Address Manually"](../../images/image (990).png>)

Giờ hãy đánh dấu vào ô "Pointer" và nhập địa chỉ tìm được vào hộp văn bản (trong trường hợp này, địa chỉ tìm được ở hình trước là "Tutorial-i386.exe"+2426B0):

![Địa chỉ bộ nhớ ngẫu nhiên - Tìm code - Địa chỉ bộ nhớ ngẫu nhiên - Tìm pointer: Giờ hãy đánh dấu vào ô "Pointer" và nhập địa chỉ tìm được vào hộp văn bản (trong trường hợp này,...](<../../images/image (392).png>)

(Lưu ý rằng "Address" đầu tiên sẽ tự động được điền từ địa chỉ pointer bạn nhập vào)

Nhấp OK để tạo pointer mới:

![Địa chỉ bộ nhớ ngẫu nhiên - Tìm code - Địa chỉ bộ nhớ ngẫu nhiên - Tìm pointer: Nhấp OK để tạo pointer mới](<../../images/image (308).png>)

Giờ đây, mỗi lần bạn thay đổi giá trị đó, bạn sẽ **thay đổi được giá trị quan trọng, ngay cả khi địa chỉ bộ nhớ lưu giá trị đó đã khác.**

### Code Injection

Code injection là kỹ thuật đưa một đoạn code vào process mục tiêu, sau đó chuyển hướng luồng thực thi để chạy qua đoạn code do bạn viết (chẳng hạn như cộng điểm thay vì trừ điểm).

Giả sử bạn đã tìm thấy địa chỉ đang trừ 1 máu của người chơi:

![Địa chỉ bộ nhớ ngẫu nhiên - Tìm pointer - Code Injection: Giả sử bạn đã tìm thấy địa chỉ đang trừ 1 máu của người chơi](<../../images/image (203).png>)

Nhấp vào Show disassembler để xem **code disassemble**.\
Sau đó, nhấn **CTRL+a** để mở cửa sổ Auto assemble và chọn _**Template --> Code Injection**_

![Địa chỉ bộ nhớ ngẫu nhiên - Tìm pointer - Code Injection: Sau đó, nhấn CTRL+a để mở cửa sổ Auto assemble và chọn Template -- Code Injection](<../../images/image (902).png>)

Điền **địa chỉ của instruction bạn muốn sửa đổi** (thường thì địa chỉ này được điền tự động):

![Địa chỉ bộ nhớ ngẫu nhiên - Tìm pointer - Code Injection: Điền địa chỉ của instruction bạn muốn sửa đổi (thường thì địa chỉ này được điền tự động)](<../../images/image (744).png>)

Một template sẽ được tạo:

![Địa chỉ bộ nhớ ngẫu nhiên - Tìm pointer - Code Injection: Một template sẽ được tạo](<../../images/image (944).png>)

Hãy chèn assembly code mới vào phần "**newmem**" và xóa code gốc khỏi phần "**originalcode**" nếu bạn không muốn nó được thực thi**.** Trong ví dụ này, code được inject sẽ cộng 2 điểm thay vì trừ 1:

![Địa chỉ bộ nhớ ngẫu nhiên - Tìm pointer - Code Injection: Hãy chèn assembly code mới vào phần "newmem" và xóa code gốc khỏi phần "originalcode" nếu bạn...](<../../images/image (521).png>)

**Nhấp vào execute, v.v. để inject code vào chương trình. Thao tác này sẽ thay đổi hành vi của chức năng!**

## Code injection an toàn khi relocation bằng AOB signature

Một script hook vào `game.exe+123456` có thể bị lỗi sau khi ASLR hoặc phần mềm được cập nhật. **Array of Bytes (AOB) signature** tìm instruction dựa trên machine code xung quanh nó. Dùng `aobscanmodule` để giới hạn tìm kiếm trong một module. Signature cần đủ dài để chỉ khớp một kết quả. Dùng wildcard cho các byte relocation, địa chỉ và những byte khác có thể thay đổi. Không dùng wildcard cho toàn bộ instruction mà bạn cần khôi phục.<sup>[[4]](#references)</sup>

Trong Memory View, chọn instruction rồi dùng **Tools → Auto Assemble → Template → AOB Injection**. Block `[DISABLE]` được tạo rất quan trọng. Block này phải khôi phục mọi byte đã bị ghi đè và giải phóng vùng nhớ đã cấp phát.<sup>[[4]](#references)</sup>

<details>
<summary>Bộ khung AOB injection x64 tối giản</summary>

```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
  movss [rbx+000000A0],xmm0
  jmp return
INJECT:
  jmp newmem
  nop
  nop
  nop
return:
[DISABLE]
INJECT:
  db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```

</details>

Trước khi bật script, hãy xác minh các điểm sau:

1. AOB trả về **một** địa chỉ. Nếu có nhiều kết quả, hãy thêm các instruction ổn định ở cả hai phía.
2. Lệnh nhảy thay thế các instruction hoàn chỉnh. Không bao giờ cắt đôi một instruction.
3. Code cave được cấp phát nằm trong phạm vi mà lệnh nhảy được tạo có thể tới. Trên x64, nếu vùng cấp phát ở xa, có thể cần lệnh nhảy 14 byte.
4. Code được inject bảo toàn các register, flag và căn chỉnh stack mà function gốc yêu cầu.
5. Khối disable khôi phục chính xác các byte ban đầu. Hãy thử bật và tắt nhiều lần trước khi lưu table.

## Quy trình tìm pointer đáng tin cậy

Pointer tìm được trong một lần chạy chỉ là ứng viên. Hãy tạo pointer map trong nhiều lần chạy mới và rescan với tất cả các map đó. Khởi động lại target giữa các lần thu thập để ASLR và các vùng cấp phát trên heap thay đổi. Ưu tiên các đường dẫn có base là module hoặc một symbol ổn định khác. Loại bỏ các đường dẫn chỉ hoạt động với một save, level hoặc instance của object.

Bộ lọc **pointer must end with specific offsets** cùng tùy chọn deviation có thể giữ lại các đường dẫn hữu ích khi một field lân cận dịch chuyển giữa các bản build. Bản phát hành 7.5 cũng bổ sung tùy chọn kiểm soát deviation này. Đây là bộ lọc, không phải bằng chứng cho thấy pointer chain ổn định.<sup>[[1]](#references)</sup>

Khi một structure dịch chuyển quá thường xuyên để pointer scanning hoạt động hiệu quả, hãy hook instruction truy cập nó. Lưu pointer object đang hoạt động từ một register vào một symbol được cấp phát. Cách này thường đáng tin cậy hơn với danh sách entity và object được quản lý.

## Trace code thay vì scan giá trị

Dùng **Find out what writes to this address** khi giá trị bị sửa đổi trực tiếp. Dùng **Find out what accesses this address** khi bạn cần tìm object sở hữu nó hoặc khi thao tác ghi diễn ra thông qua dữ liệu đã được sao chép. Chỉ thực hiện một hành động trong target. Sau đó, so sánh số lần trúng và trạng thái register.

**Ultimap 2** sử dụng Intel Processor Trace trên các CPU Intel được hỗ trợ. Công cụ này ghi lại luồng điều khiển đã thực thi và ít gây gián đoạn hơn so với việc step từng instruction. Lọc các đoạn code đã thực thi trong lúc hành động cần quan tâm diễn ra, rồi loại bỏ những đoạn cũng xuất hiện trong lần capture khi target ở trạng thái nhàn rỗi. Intel PT không phải tính năng ẩn mình. Target vẫn có thể phát hiện việc tracing, thay đổi timing hoặc chính Cheat Engine.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 cũng bổ sung giao diện Intel PT do Windows cung cấp. Chế độ Ultimap cũ dựa trên DBVM và chế độ Intel PT có yêu cầu phần cứng và OS khác nhau. Đừng cho rằng CPU hỗ trợ DBVM cũng hỗ trợ Intel PT.<sup>[[1]](#references)</sup>

## Chọn debugger và breakpoint

Chọn debugger ít xâm lấn nhất nhưng vẫn hoạt động:

- **Windows debugger** đơn giản nhưng tạo ra các debug event thông thường. Các kiểm tra anti-debugging có thể phát hiện nó.
- **VEH debugger** xử lý breakpoint thông qua vectored exception handler. Nó tránh được một số kiểm tra debugger cơ bản nhưng không vô hình.
- **Hardware breakpoint** không sửa các byte của instruction, nhưng x86/x64 chỉ cung cấp một số lượng nhỏ slot debug-register.
- **Software breakpoint** thay một byte bằng `INT3`. Cách này dễ bị phát hiện và có thể xung đột với các kiểm tra integrity.
- **DBVM debugger** đưa một số thao tác xuống dưới guest OS. Nó có nhiều quyền hơn và có thể làm host bị crash nếu cấu hình sai.

Cheat Engine 7.5 có thể dùng lệnh nhảy một byte dựa trên exception handler và `INT3` khi không đủ chỗ cho lệnh nhảy relative thông thường. Hãy xem nó như một software breakpoint. Xác minh luồng exception và đừng cho rằng nó vượt qua được các kiểm tra anti-tamper.<sup>[[1]](#references)</sup>

DBVM là hypervisor, không phải công tắc giúp ẩn mình trong mọi tình huống. Chỉ sử dụng nó trong lab dùng một lần. Không để lộ giao diện điều khiển của nó cho code không đáng tin cậy. Anti-cheat cấp kernel và các sản phẩm endpoint vẫn có thể phát hiện driver, trạng thái hypervisor hoặc memory đã bị sửa đổi.

## Runtime được quản lý và các tính năng mới trong 7.6/7.7

Với các target Mono, IL2CPP, .NET và Java, hãy ưu tiên metadata của runtime thay vì blind scan nếu có thể. Mở **Mono → Activate mono features** hoặc cửa sổ thông tin runtime tương ứng. Trước tiên, xác định class, field hoặc method. Sau đó dùng native disassembly khi method được managed đã được JIT compile.

Nhánh 7.6 bổ sung `AOBSCANEX` để chỉ tìm signature trong executable memory, giao diện debugger `gdbserver`, khả năng kiểm tra Java metadata, duyệt IL2CPP nhanh hơn và tùy chọn pointer-scan bỏ qua byte cao của pointer được dùng cho ARM memory tagging. Nhánh 7.7 bổ sung bản native cho Linux, `HOOK`/`UNHOOK`, `aobscanfunction`, khả năng tìm generic Mono method tốt hơn, hỗ trợ PDB structure được cải thiện và khả năng phân tích structure cơ bản của Unreal Engine.<sup>[[3]](#references)</sup>

Các bổ sung này hỗ trợ một quy trình hữu ích:

1. Xác định managed method hoặc static field từ metadata.
2. Trace hoặc disassemble native code được tạo cho method đó.
3. Dùng `AOBSCANEX` hoặc `aobscanfunction` để tìm một executable signature ổn định.
4. Tạo một hook có thể hoàn tác. Giữ lại các instruction gốc và xác thực đường dẫn disable.
5. Kiểm tra lại signature sau mỗi lần target được cập nhật. Tìm thấy kết quả khớp không đảm bảo logic xung quanh vẫn giữ nguyên ý nghĩa.

## Target từ xa với `ceserver`

`ceserver` cung cấp khả năng liệt kê process, truy cập memory và debugging cho giao diện Cheat Engine. Các bản build chính thức hỗ trợ Linux và Android. Chạy đúng kiến trúc trên target rồi kết nối qua tab **Network**. Trên Android, chuyển tiếp port mặc định sẽ tránh phải để port lộ ra mạng:<sup>[[3]](#references)</sup>

```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```

Bridge bên thứ ba `frida-ceserver` có thể cung cấp giao diện tương thích với Cheat Engine cho các mục tiêu iOS. Đây không phải `ceserver` chính thức và các thao tác được hỗ trợ có thể khác nhau.<sup>[[2]](#references)</sup>

Giả định rằng giao thức cấp quyền truy cập ở cấp debugger. Hãy liên kết nó với loopback hoặc đặt nó sau một SSH/ADB tunnel. Tuyệt đối không để TCP 52736 lộ ra mạng không đáng tin cậy. Dừng server khi kết thúc phiên.

## An toàn vận hành

Chỉ attach vào phần mềm mà bạn sở hữu hoặc được phép kiểm thử. Không chạy Cheat Engine bên cạnh trò chơi trực tuyến hoặc endpoint production. Các thao tác ghi bộ nhớ, code được inject, driver và DBVM có thể làm crash hoặc hỏng mục tiêu.<sup>[[3]](#references)</sup>

Tải các bản build từ trang chính thức hoặc compile source đã công bố. Các sản phẩm bảo mật thường phân loại memory editor, debugger và driver của chúng là hack tools. Không tắt toàn bộ biện pháp bảo vệ trên host. Hãy dùng VM hoặc host lab chuyên dụng và xác minh artifact trước khi chạy.<sup>[[3]](#references)</sup>



## References

- [1] [Ghi chú phát hành Cheat Engine 7.5](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [Bridge frida-ceserver dành cho mục tiêu từ xa](https://github.com/gmh5225/frida-ceserver)
- [3] [Tin tức phát hành chính thức của Cheat Engine](https://www.cheatengine.org/)
- [4] [Wiki Cheat Engine: AOB trong Auto Assembler](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
