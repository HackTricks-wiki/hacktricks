# Công cụ Reversing & các phương pháp cơ bản

{{#include ../../banners/hacktricks-training.md}}

## Công cụ reversing dựa trên ImGui

Phần mềm:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Tự động hóa WinDbg ở chế độ user-mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Luồng điều khiển dựa trên exception của Windows

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Debug kernel Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Trình decompiler Wasm / trình biên dịch Wat

Trực tuyến:

- Dùng [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) để **decompile** từ wasm (dạng binary) sang wat (văn bản dễ đọc)
- Dùng [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) để **compile** từ wat sang wasm
- Bạn cũng có thể thử [web-wasmdec](https://wwwg.github.io/web-wasmdec/) để decompile.

Phần mềm:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode đã cache của Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payload được virtualize và VM tùy chỉnh

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Trình decompiler .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek là một trình decompiler có thể **decompile và kiểm tra nhiều định dạng**, bao gồm **library** (.dll), **file metadata của Windows** (.winmd) và **file thực thi** (.exe). Sau khi decompile, có thể lưu assembly dưới dạng project Visual Studio (.csproj).

Điểm hữu ích là nếu cần khôi phục mã nguồn bị thất lạc từ một assembly cũ, thao tác này có thể tiết kiệm thời gian. Ngoài ra, dotPeek cung cấp tính năng điều hướng thuận tiện trong mã đã decompile, khiến nó trở thành một trong những công cụ lý tưởng để **phân tích thuật toán Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Với mô hình add-in toàn diện và API cho phép mở rộng công cụ để đáp ứng chính xác nhu cầu của bạn, .NET Reflector giúp tiết kiệm thời gian và đơn giản hóa quá trình phát triển. Hãy cùng xem qua những dịch vụ reverse engineering đa dạng mà công cụ này cung cấp:

- Giúp hiểu cách dữ liệu di chuyển qua một library hoặc component
- Giúp hiểu cách triển khai và sử dụng các ngôn ngữ và framework .NET
- Tìm các chức năng chưa được tài liệu hóa hoặc chưa được công khai để khai thác tốt hơn các API và công nghệ đang dùng.
- Tìm các dependency và những assembly khác nhau
- Xác định chính xác vị trí lỗi trong code, component của bên thứ ba và library.
- Debug vào source của toàn bộ code .NET mà bạn làm việc cùng.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy cho Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Có thể dùng trên mọi OS (bạn có thể cài trực tiếp từ VSCode, không cần tải git. Nhấp vào **Extensions** rồi **tìm ILSpy**).\
Nếu cần **decompile**, **chỉnh sửa** rồi **recompile**, bạn có thể dùng [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) hoặc fork của nó đang được duy trì tích cực là [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** để thay đổi nội dung bên trong một hàm).

### Kiểm tra managed code không cần thực thi bằng REA

**REA** có thể kiểm tra metadata PE/CLI và CIL mà không cần nạp assembly. Hãy bắt đầu bằng cách xác định artifact, sau đó kiểm tra các member và ranh giới native được khai báo; cách này hữu ích khi xem xét các lời gọi đáng ngờ trước khi dùng decompiler hoặc chạy chương trình.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Khi so sánh các phiên bản, `compare_managed_members` sử dụng danh tính CIL/chữ ký thô và dấu vân tay của các instruction đã giải mã, thay vì xem metadata token là ổn định giữa các bản dựng. Khai báo P/Invoke không chứng minh rằng mã native đã chạy; `verify_managed_native_boundaries` cần có native export hoặc bằng chứng về function tương ứng để kiểm tra ranh giới đó. Hãy lưu kèm digest của artifact, MVID và các mapping chưa được phân giải trong kết quả.<sup>[[17]](#references)</sup>

### Ghi nhật ký DNSpy

Để **DNSpy ghi một số thông tin vào file**, bạn có thể dùng đoạn mã sau:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Gỡ lỗi bằng DNSpy

Để gỡ lỗi mã bằng DNSpy, bạn cần:

Trước tiên, thay đổi **các thuộc tính Assembly** liên quan đến **gỡ lỗi**:

![DNSpy Logging - Gỡ lỗi bằng DNSpy: Trước tiên, thay đổi các thuộc tính Assembly liên quan đến gỡ lỗi](<../../images/image (973).png>)

Từ:

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

Đến:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

Và nhấp vào **compile**:

![DNSpy Logging - DNSpy Debugging: Và nhấp vào compile](<../../images/image (314) (1).png>)

Sau đó lưu tệp mới bằng _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Sau đó lưu tệp mới bằng File Save module](<../../images/image (602).png>)

Việc này cần thiết vì nếu không làm vậy, khi **runtime**, mã sẽ được áp dụng một số **tối ưu hóa**, và có thể xảy ra trường hợp khi debug, **breakpoint không bao giờ được kích hoạt** hoặc một số **biến không tồn tại**.

Sau đó, nếu ứng dụng .NET của bạn đang được **chạy** bởi **IIS**, bạn có thể **khởi động lại** ứng dụng bằng:

```
iisreset /noforce
```

Sau đó, để bắt đầu debug, hãy đóng tất cả các file đang mở và trong **Debug Tab**, chọn **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Sau đó, để bắt đầu debug, hãy đóng tất cả các file đang mở và trong Debug Tab, chọn Attach to Process](<../../images/image (318).png>)

Tiếp theo, chọn **w3wp.exe** để attach vào **IIS server** rồi nhấp **attach**:

![DNSpy Logging - DNSpy Debugging: Tiếp theo, chọn w3wp.exe để attach vào IIS server rồi nhấp attach](<../../images/image (113).png>)

Giờ ta đang debug process, đã đến lúc tạm dừng và tải tất cả module. Trước tiên, nhấp _Debug >> Break All_, sau đó nhấp _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Giờ ta đang debug process, đã đến lúc tạm dừng và tải tất cả module. Trước tiên, nhấp vào Debug Break All, sau đó nhấp vào Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Giờ ta đang debug process, đã đến lúc tạm dừng và tải tất cả module. Trước tiên, nhấp vào Debug Break All, sau đó nhấp vào Debug Windows Modules](<../../images/image (834).png>)

Nhấp vào bất kỳ module nào trong **Modules** rồi chọn **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Nhấp vào bất kỳ module nào trong Modules rồi chọn Open All Modules](<../../images/image (922).png>)

Nhấp chuột phải vào bất kỳ module nào trong **Assembly Explorer** rồi nhấp **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Nhấp chuột phải vào bất kỳ module nào trong Assembly Explorer rồi nhấp Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Tải rundll32** (bản 64bits ở C:\Windows\System32\rundll32.exe và bản 32 bits ở C:\Windows\SysWOW64\rundll32.exe)
- Chọn debugger **Windbg**
- Chọn "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Chọn " Suspend on library load/unload "](<../../images/image (868).png>)

- Cấu hình **parameters** khi thực thi bằng cách điền **path đến DLL** và function bạn muốn gọi:

![Debugging DLLs - Using IDA: Cấu hình parameters khi thực thi bằng cách điền path đến DLL và function bạn muốn gọi](<../../images/image (704).png>)

Sau đó, khi bắt đầu debug, **process sẽ tạm dừng mỗi khi một DLL được tải**. Vì vậy, khi rundll32 tải DLL của bạn, process sẽ tạm dừng.

Phương pháp này tạm dừng tại các sự kiện tải module, nhưng việc đi đến entry point của DLL đã tải không trực tiếp bằng workflow x64dbg bên dưới.

### Using x64dbg/x32dbg

- **Tải rundll32** (bản 64bits ở C:\Windows\System32\rundll32.exe và bản 32 bits ở C:\Windows\SysWOW64\rundll32.exe)
- **Thay đổi Command Line** ( _File --> Change Command Line_ ) và đặt path của DLL cùng function bạn muốn gọi, ví dụ: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Thay đổi _Options --> Settings_ rồi chọn "**DLL Entry**".
- Sau đó, **bắt đầu thực thi**. Debugger sẽ tạm dừng tại main của mỗi DLL; đến một thời điểm nào đó, bạn sẽ **dừng tại Entry của DLL mình**. Từ đó, chỉ cần tìm các vị trí bạn muốn đặt breakpoint.

Lưu ý rằng khi process bị tạm dừng vì bất kỳ lý do nào trong win64dbg, bạn có thể xem **mình đang ở đoạn code nào** ở **phía trên cửa sổ win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Lưu ý rằng khi process bị tạm dừng vì bất kỳ lý do nào trong win64dbg, bạn có thể xem mình đang ở đoạn code nào ở phía trên cửa sổ win64dbg](<../../images/image (842).png>)

Chỉ báo này xác nhận rằng process đã tạm dừng bên trong DLL bạn muốn debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) là một chương trình hữu ích để tìm nơi lưu các giá trị quan trọng trong memory của một game đang chạy và thay đổi chúng. Xem thêm tại:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) là công cụ front-end/reverse engineering cho GNU Project Debugger (GDB), tập trung vào game. Tuy nhiên, công cụ này có thể dùng cho mọi tác vụ liên quan đến reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) là front-end trên web cho nhiều decompiler. Dịch vụ web này cho phép bạn so sánh kết quả của các decompiler khác nhau trên những executable nhỏ.

## Điều tra native có bằng chứng với REA

**REA** cung cấp khả năng phân tích bằng Hopper, Ghidra và IDA thông qua CLI và MCP. Công cụ yêu cầu Node.js 22.x (tối thiểu 22.19), 24.x (tối thiểu 24.11) hoặc 26+, cùng với npm. Trước tiên, hãy cấu hình một native provider hiện có; kiểm tra `rea providers --json` và chọn provider một cách rõ ràng nếu có nhiều provider hỗ trợ target. Thay `0x1000` bên dưới bằng tên hoặc địa chỉ function được quan sát trong inventory.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Bắt đầu từ một chuỗi tính năng hoặc symbol, lần theo các tham chiếu và caller, sau đó kiểm tra hồ sơ function đã chọn cùng pseudocode bằng `rea decompile`. REA gắn một session với provider đã chọn thay vì âm thầm thay thế provider đó khi xảy ra lỗi. Để truy vấn có thể lặp lại, `--snapshot PATH` chỉ dùng lại các byte artifact, provider, cài đặt, operation và tham số khớp nhau; snapshot là bộ nhớ đệm cục bộ, không phải cơ sở dữ liệu provider đã lưu. Giữ nguyên Evidence được trả về và các phần chưa rõ được nêu rõ, thay vì xem các đường dẫn suy luận hoặc văn bản decompiler là mã nguồn gốc.<sup>[[16]](#references)[[18]](#references)</sup>

Đối với các entry point JavaScript/Electron dẫn vào native add-on, xem [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Phân tích IDA và Ghidra bằng script với cầu nối TCP cục bộ

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) chạy bên trong một cơ sở dữ liệu IDA hoặc chương trình Ghidra CodeBrowser **đã mở sẵn**, cho phép một script riêng biệt truy vấn và sửa đổi cơ sở dữ liệu phân tích đó. Chạy `ID_Server.py` từ Python CLI của IDA (`import ID_Server`) hoặc `Ghidra_Server.py` từ Script Manager của Ghidra. IDA bind vào `127.0.0.1`, bắt đầu từ port `5073` và quét các port cao hơn. Script Ghidra hiện tại bắt đầu từ port `5093` và thử mười port cho đến `5102`; socket Java của nó bind vào địa chỉ wildcard, không chỉ loopback. Kiểm tra port được instance in ra trước khi kết nối. Không giống headless analyzer, bridge này hoạt động trên chương trình hiện đang mở trong instance GUI đó.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Gửi **mỗi kết nối một command kết thúc bằng newline** và đọc response kết thúc bằng newline. Kết quả thường là JSON. Ví dụ, sau khi tìm thấy một API được import có liên quan đến đường dẫn đầu vào, `IMPORTXREF` tìm các call site của API đó; tiếp theo, `DECOMP_XREF` decompile hàng loạt các caller của một địa chỉ đã chọn. `FUNC` kiểm tra một function, còn `PCODE` trả về biểu diễn trung gian của decompiler. Dùng địa chỉ từ cơ sở dữ liệu đang hoạt động, không dùng địa chỉ được sao chép từ một binary đã được rebase khác. Ví dụ bên dưới dùng port mặc định của IDA; với Ghidra, hãy dùng port được script in ra.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Kênh tương tự có thể **thay đổi cơ sở dữ liệu phân tích**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` và `PATCH` thay đổi tên, kiểu, định nghĩa cấu trúc, ranh giới hàm hoặc byte được lưu trữ. `PATCH` là thao tác chỉnh sửa cơ sở dữ liệu, **không phải** bằng chứng cho thấy có bản vá trên tiến trình đang chạy. Không listener nào tài liệu hóa việc xác thực. IDA chỉ lắng nghe trên loopback, nhưng Ghidra có thể truy cập qua các giao diện mạng; hãy hạn chế quyền truy cập vào listener của Ghidra khi sử dụng. `QUIT` dừng một trong hai listener, còn IDA cũng cung cấp `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debug shellcode bằng blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) cấp phát **shellcode**, in ra **địa chỉ bộ nhớ** của nó và tạm dừng thực thi.\
Gắn debugger như IDA hoặc x64dbg, đặt breakpoint tại địa chỉ được in ra, rồi tiếp tục thực thi để debug shellcode.

Trang GitHub releases có các tệp zip chứa những bản phát hành đã biên dịch: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Bạn có thể tìm thấy một phiên bản BlobRunner đã chỉnh sửa đôi chút tại liên kết sau. Để biên dịch, chỉ cần **tạo một dự án C/C++ trong Visual Studio Code, sao chép và dán mã rồi build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debug shellcode bằng jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) tương tự BlobRunner. Nó cấp phát shellcode rồi đi vào một vòng lặp vô hạn. Gắn debugger, tiếp tục thực thi trong **2–5 giây**, tạm dừng bên trong vòng lặp đó, rồi step đến lệnh gọi tiếp theo chuyển quyền thực thi sang shellcode đã cấp phát.

![Debugger tạm dừng trong vòng lặp vô hạn của jmp2it, ngay trước lệnh gọi đến shellcode đã cấp phát](<../../images/image (509).png>)

Bạn có thể tải phiên bản đã biên dịch của [jmp2it tại trang releases](https://github.com/adamkramer/jmp2it/releases/).

### Debug shellcode bằng Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) là GUI của radare. Dùng Cutter, bạn có thể giả lập shellcode và kiểm tra nó khi đang chạy.

Lưu ý rằng Cutter cho phép bạn chọn "Open File" và "Open Shellcode". Trong trường hợp của tôi, khi mở shellcode dưới dạng tệp, nó decompile chính xác, nhưng khi mở dưới dạng shellcode thì không:

![Cutter hiển thị kết quả phân tích khác nhau khi mở cùng một byte dưới dạng tệp hoặc shellcode](<../../images/image (562).png>)

Để bắt đầu giả lập tại vị trí mong muốn, hãy đặt bp ở đó; có vẻ như Cutter sẽ tự động bắt đầu giả lập từ vị trí đó:

![Đặt breakpoint tại entry của shellcode mong muốn trước khi bắt đầu giả lập trong Cutter](<../../images/image (589).png>)

![Trình giả lập Cutter tạm dừng tại breakpoint shellcode đã chọn](<../../images/image (387).png>)

Ví dụ, bạn có thể xem stack trong một hex dump:

![Xem stack shellcode được giả lập trong hex dump của Cutter](<../../images/image (186).png>)

### Deobfuscate shellcode và tìm các hàm được thực thi

Bạn nên thử [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Công cụ này sẽ cho bạn biết những thông tin như shellcode đang dùng **những hàm nào** và liệu nó có đang **giải mã** chính nó trong bộ nhớ hay không.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg cũng có trình khởi chạy đồ họa, cho phép bạn chọn các tùy chọn mong muốn và thực thi shellcode

![Trình khởi chạy đồ họa scDbg để chọn các tùy chọn mô phỏng và truy vết shellcode](<../../images/image (258).png>)

Tùy chọn **Create Dump** sẽ dump shellcode cuối cùng nếu shellcode được thay đổi động trong bộ nhớ (hữu ích để tải xuống shellcode đã giải mã). **start offset** có thể hữu ích khi muốn bắt đầu chạy shellcode từ một offset cụ thể. Tùy chọn **Debug Shell** hữu ích để debug shellcode bằng terminal scDbg (tuy nhiên, tôi thấy các tùy chọn đã giải thích trước đó phù hợp hơn cho việc này vì bạn có thể dùng Ida hoặc x64dbg).

### Disassemble bằng CyberChef

Tải tệp shellcode lên làm đầu vào và dùng recipe sau để dịch ngược nó: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Gỡ obfuscation MBA

Obfuscation **Mixed Boolean-Arithmetic (MBA)** che giấu các biểu thức đơn giản như `x + y` bằng các công thức kết hợp phép toán số học (`+`, `-`, `*`) với toán tử bitwise (`&`, `|`, `^`, `~`, dịch bit). Điểm quan trọng là các đồng nhất thức này thường chỉ đúng trong **phép toán modular có độ rộng cố định**, vì vậy carry và tràn số rất quan trọng:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Nếu đơn giản hóa biểu thức kiểu này bằng công cụ đại số tổng quát, bạn có thể dễ dàng nhận được kết quả sai vì ngữ nghĩa độ rộng bit đã bị bỏ qua.<sup>[[1]](#references)</sup>

### Quy trình thực tế

1. **Giữ nguyên độ rộng bit** của mã/IR/decompiler output đã được nâng lên (`8/16/32/64` bits).
2. **Phân loại biểu thức** trước khi thử đơn giản hóa:
   - **Tuyến tính**: tổng có trọng số của các thành phần bitwise
   - **Bán tuyến tính**: tuyến tính cộng với các mask hằng như `x & 0xFF`
   - **Đa thức**: có phép nhân
   - **Hỗn hợp**: phép nhân và logic bitwise đan xen, thường có các biểu thức con lặp lại
3. **Xác minh mọi phép biến đổi ứng viên** bằng kiểm thử ngẫu nhiên hoặc chứng minh SMT. Nếu không thể chứng minh tính tương đương, hãy giữ nguyên biểu thức ban đầu thay vì phỏng đoán.

### Bỏ qua control flow đã flatten bằng một lát thực thi hẹp

Thường không cần khôi phục toàn bộ control-flow graph. Khi gặp control-flow flattening, opaque predicates, dispatcher lớn hoặc mã nặng MBA, hãy lần theo tham chiếu từ các blob được mã hóa và buffer đầu ra đến routine nhỏ nhất có nhiệm vụ biến đổi chúng. Sau đó chỉ cần tái tạo lát data-flow đó hoặc thực thi riêng nó; dispatcher không cần thiết nếu có thể khởi tạo trực tiếp trạng thái liên quan.<sup>[[7]](#references)</sup>

Quy trình thực tế:<sup>[[7]](#references)</sup>

1. Kiểm kê các section executable và data, relocation, cùng các cross-reference. Dump các bảng khả nghi từ `.rodata`, giữ nguyên thứ tự byte và độ rộng phần tử.
2. Xác định routine cuối cùng ghi plaintext hoặc buffer đầu ra. Ghi lại các đầu vào, bảng được tham chiếu, lời gọi đã import và trạng thái global cần thiết.
3. Chỉ chuyển các phép toán đó thành mô hình Python có độ rộng cố định. Nếu lát này vẫn phụ thuộc quá nhiều vào trạng thái, hãy gọi routine bằng Unicorn, QEMU hoặc debugger và hook các import không liên quan thay vì giả lập toàn bộ chương trình.
4. Xác minh extractor thực sự tạo đầu ra từ binary được cung cấp: loại bỏ fallback im lặng, tìm kiếm câu trả lời được nhúng trong đó và chạy extractor trên các bản build chưa từng thấy có strings, keys, identifiers, layouts và obfuscation seeds đã thay đổi.

Các lệnh hữu ích để bắt đầu:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Phát hiện các biểu thức MBA ngụy trang hằng số

Một biểu thức byte có vẻ phụ thuộc vào đầu vào có thể triệt tiêu hoàn toàn đầu vào đó. Sau khi trích xuất các bảng, hãy đánh giá biểu thức trên toàn bộ miền 8-bit; nếu tập đầu ra chỉ có một giá trị, điều đó chứng minh byte đó là hằng số mà không cần khôi phục state machine bao quanh.<sup>[[7]](#references)</sup>

```python
def mba(a, b, c, d, e, x):
    return ((((a | (~x & 0xff)) & c) +
             ((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
    outputs = {mba(*row, x) for x in range(256)}
    if len(outputs) != 1:
        raise ValueError("expression depends on x")
    decoded.append(outputs.pop())
print(decoded)
```

Giữ lại mask cuối cùng vì phép cộng ban đầu có hiện tượng tràn vòng theo độ rộng byte. Với miền rộng hơn, hãy hỏi SMT solver xem `f(x1) != f(x2)` có thỏa mãn với hai đầu vào ký hiệu cùng độ rộng hay không: `unsat` chứng minh tính bất biến, còn `sat` đưa ra một phản ví dụ và có nghĩa là không thể loại bỏ đầu vào.<sup>[[7]](#references)</sup>

#### Nhận diện giải mã phụ thuộc môi trường

Các bước kiểm tra anti-analysis không nhất thiết phải rẽ nhánh hoặc gây crash. Bộ giải mã có thể trộn kết quả cảm biến vào bit khóa, hằng số opaque predicate hoặc trạng thái flattened-dispatcher, tiếp tục chạy bình thường và tạo ra plaintext có vẻ hợp lý nhưng sai trong emulator. Vì vậy, chỉ patch các nhánh lỗi hiển thị là chưa đủ; hãy lần theo các phụ thuộc dữ liệu từ các phép dò môi trường đến trạng thái bộ giải mã, so sánh cùng một lát mã trên thiết bị thật và emulator, rồi kiểm tra cách việc ép kết quả của từng cảm biến làm thay đổi buffer cuối cùng.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) là công cụ đơn giản hóa MBA thực tiễn dành cho phân tích malware và reversing binary được bảo vệ. Công cụ phân loại biểu thức rồi chuyển biểu thức qua các pipeline chuyên biệt thay vì áp dụng một lượt viết lại chung cho mọi thứ.<sup>[[2]](#references)</sup>

Cách dùng nhanh:

```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```

Các trường hợp hữu ích:

- **Linear MBA**: CoBRA đánh giá biểu thức trên các đầu vào Boolean, suy ra chữ ký và chạy song song một số phương pháp khôi phục như so khớp mẫu, chuyển đổi ANF và nội suy hệ số.
- **Semilinear MBA**: Các atom được mask bằng hằng số được dựng lại bằng phương pháp tái dựng phân vùng bit để các vùng được mask vẫn chính xác.
- **Polynomial/Mixed MBA**: Các tích được phân rã thành lõi, và các biểu thức con lặp lại có thể được đưa vào biến tạm trước khi đơn giản hóa quan hệ bên ngoài.

Ví dụ về một đẳng thức hỗn hợp thường đáng thử khôi phục:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Điều này có thể được rút gọn thành:

```c
x * y
```

### Ghi chú về reversing

- Ưu tiên chạy CoBRA trên **biểu thức IR đã nâng cấp** hoặc đầu ra decompiler sau khi đã cô lập phép tính chính xác.
- Dùng `--bitwidth` một cách tường minh khi biểu thức bắt nguồn từ phép toán có mask hoặc thanh ghi hẹp.
- Nếu cần bước chứng minh mạnh hơn, hãy xem ghi chú Z3 tại đây:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA cũng đi kèm dưới dạng **plugin LLVM pass** (`libCobraPass.so`), hữu ích khi bạn muốn chuẩn hóa LLVM IR có nhiều MBA trước các pass phân tích tiếp theo.
- Các phần dư hỗn hợp miền nhạy với carry nhưng không được hỗ trợ nên được xem là dấu hiệu cần giữ nguyên biểu thức ban đầu và tự phân tích đường đi của carry.

## Khôi phục control-flow flattening dùng trạng thái XOR

Một flattener kiểu OLLVM có thể lưu trạng thái basic block hiện tại trong hai thanh ghi 64-bit và dựng lại trạng thái bằng XOR tại dispatcher. Mỗi block gốc ghi cặp giá trị ứng với trạng thái tiếp theo rồi nhảy về dispatcher. Một block có điều kiện có thể dùng `CMOVcc` để thay thế một nửa của cặp theo các cờ CPU, vì vậy chỉ theo dõi các lệnh nhánh hiển thị sẽ bỏ sót hai successor. Khác với dispatcher dùng indirect-jump, kiểu này có thể chỉ sử dụng các back-edge trực tiếp.<sup>[[19]](#references)[[20]](#references)</sup>

Để khôi phục đồ thị, hãy xác định cây so sánh của dispatcher và hai thanh ghi trạng thái, ánh xạ từng trạng thái XOR được so sánh tới block đích, sau đó lần theo các lệnh ghi đến cặp thanh ghi trong mỗi block gốc. Với các lệnh ghi có điều kiện, hãy xét cả lệnh thiết lập cờ và hai kết quả `CMOVcc`. Viết lại lối ra dispatcher của từng block thành successor trực tiếp đã xác định hoặc nhánh có điều kiện; khi đó dispatcher sẽ không còn được truy cập mà không cần vá binary. Đây là cách tiếp cận toàn bộ CFG; nếu chỉ một decoder quan trọng, workflow [narrow execution-slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) ở trên có thể nhanh hơn.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) tự động hóa kiểu này trong Binary Ninja. Sao chép `plugins/DispatchThis` vào thư mục plugin người dùng của Binary Ninja rồi khởi động lại. Trên function bị ảnh hưởng, mở **Function Settings** và chọn `OLLVM_XOR_64`; nếu phân tích không bắt đầu, hãy dùng **Analysis → Reanalyze All Functions**. Chế độ này viết lại các cạnh control-flow của MLIL, không thay đổi byte trong file và không cần Z3 hay indirect-jump resolver. Công cụ đã được thử nghiệm trên Binary Ninja 5.3.9757+; nó không xóa các lệnh ghi trạng thái theo từng block đã chết, vì vậy đừng nhầm chúng với các chuyển trạng thái vẫn còn hoạt động.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator này thay các thao tác của chương trình bằng các chuỗi lệnh dựa trên `mov` và dùng xử lý signal/exception để thay đổi control flow. Xem chi tiết:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Với các binary được hỗ trợ, [demovfuscator](https://github.com/kirschju/demovfuscator) có thể deobfuscate kết quả. Công cụ này có một số dependency.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [cài đặt keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Nếu bạn đang chơi **CTF, cách giải quyết này để tìm flag** có thể rất hữu ích: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Để tìm **entry point**, hãy tìm các hàm có tên chứa `::main`, như sau:

![Tìm entry point của Rust trong Ghidra bằng cách tìm tên hàm chứa hai dấu hai chấm theo sau là main](<../../images/image (1080).png>)

Trong trường hợp này, binary có tên là authenticator, nên khá rõ ràng đây là hàm main đáng chú ý.\
Dựa vào **tên** của các **hàm** được gọi, hãy tìm kiếm chúng trên **Internet** để tìm hiểu về **đầu vào** và **đầu ra** của chúng.

### Khôi phục chuỗi Rust từ firmware ELF

Trong các binary **Rust ELF**, nhiều chuỗi tĩnh không được tham chiếu bằng con trỏ kết thúc bằng NUL kiểu C. Một bố cục phổ biến của `rustc` là **bộ đôi con trỏ/độ dài** nằm trong **`.data.rel.ro`**, trỏ đến vùng chứa chuỗi thực sự được lưu trong **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Điều này có nghĩa là `strings` hoặc phân tích mặc định của Ghidra có thể gộp các chuỗi liền kề hoặc bỏ sót hoàn toàn các tham chiếu chéo.<sup>[[3]](#references)</sup>

Quy trình nhanh:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Lấy địa chỉ ảo và kích thước của **`.rodata`**.
2. Liệt kê **`.data.rel.ro`** từng word một.
3. Xem mọi giá trị nằm trong phạm vi địa chỉ của `.rodata` là một con trỏ chuỗi tiềm năng.
4. Xem word tiếp theo là độ dài tiềm năng.
5. Áp dụng các bộ lọc hợp lý (ví dụ: giữ các độ dài từ **4** đến **100** byte).
6. Đọc chính xác `length` byte từ `.rodata` thay vì quét cho đến khi gặp `0x00`.

Logic extractor tối thiểu:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Điều này đặc biệt hữu ích khi reversing firmware vì các chuỗi Rust được khôi phục thường tiết lộ **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers và logic liên quan đến auth**.

Nếu Ghidra bỏ sót các chuỗi đó, hãy chạy script/plugin tùy chỉnh áp dụng cùng heuristic và tạo dữ liệu chuỗi tại các offset `.rodata` được tham chiếu. Các công cụ `rust-strings` và `RustStrings.py` do Pen Test Partners công bố là tài liệu tham khảo hữu ích để điều chỉnh ý tưởng này cho các **word size, endianness và bố cục section** khác.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Đối với các binary được biên dịch bằng Delphi, bạn có thể dùng [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Nếu cần reverse một binary Delphi, tôi khuyên bạn nên dùng plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Nhấn **Alt+F7** trong IDA để tải plugin Python, sau đó chọn file plugin.

Plugin này sẽ thực thi binary và phân giải động tên các function khi bắt đầu debugging. Sau khi bắt đầu debugging, nhấn lại nút Start (nút màu xanh lá hoặc f9) để breakpoint dừng ở đầu phần code thực.

Nếu nhấn một nút trong ứng dụng đồ họa, debugger có thể dừng tại function được nút đó gọi.

## Golang

Đối với các binary Go thông thường, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) có thể khôi phục các cấu trúc runtime và cải thiện tên function trong IDA. Tải plugin Python bằng **Alt+F7**.

Nếu cần reverse một binary Golang, tôi khuyên bạn nên dùng plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Nhấn **Alt+F7** trong IDA để tải plugin Python, sau đó chọn file plugin.

Công cụ này sẽ phân giải tên các function.

### Khôi phục metadata mà không cần symbol table

Một file thực thi Go đã bị strip vẫn cần metadata runtime để ánh xạ program counter sang function. [GoReSym](https://github.com/mandiant/GoReSym) tìm và phân tích các cấu trúc như `pclntab` và `moduledata` bằng code có nguồn gốc từ Go runtime. Công cụ này có thể khôi phục ranh giới function, tên, đường dẫn source, kiểu dữ liệu và thông tin build mà không cần dựa vào symbol table thông thường.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Một obfuscator có thể giữ cho các cấu trúc đó vẫn dùng được trong khi thay thế các tên đã khôi phục. Ví dụ, Garble băm các identifier và package path, đồng thời xóa thông tin build, module và debug.<sup>[[12]](#references)</sup> Token package đã bị obfuscate phải nhất quán giữa các function thuộc package đó. Nhóm các function theo token lặp lại, suy luận một package dựa trên các callee, string và API của nó, sau đó áp dụng nhãn package đó cho toàn bộ nhóm.<sup>[[13]](#references)</sup>

### Khôi phục tên Garble bằng GoResolver

[GoResolver](https://github.com/volexity/GoResolver) kết hợp việc trích xuất runtime symbol với tạo tham chiếu sạch và đối chiếu control-flow graph (CFG). Thực hiện theo trình tự sau:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Xác định phiên bản compiler.** Trước tiên, thử `BuildInfo` và các version string được nhúng. Nếu obfuscator đã xóa chúng, hãy so sánh các phần của Go runtime đi kèm với các runtime tham chiếu theo phiên bản. Trong các bài kiểm thử của Volexity, khoảng `2%` runtime là đủ để phân biệt các phiên bản Go chính. Hãy xem đây là một tối ưu hóa dựa trên thực nghiệm, không phải ngưỡng áp dụng phổ quát.<sup>[[13]](#references)</sup>
2. **Tạo các bản tham chiếu tương thích.** Tạo binary sạch cho phiên bản Go đã xác định, kiến trúc đích và các thư viện có khả năng được sử dụng. Khớp toolchain giúp giảm khác biệt CFG do compiler tạo ra.<sup>[[10]](#references)[[13]](#references)</sup>
3. **So sánh các function.** GoGrapher đối chiếu CFG của các function và đưa ra điểm số đã chuẩn hóa từ `0.0` đến `1.0`. Việc đối chiếu basic block dựa trên so sánh có trọng số giữa các instruction tương tự. Các kết quả khớp có độ tin cậy cao ánh xạ function đã được ngẫu nhiên hóa sang phần triển khai sạch. Kết quả khớp yếu hơn vẫn có thể xác định package hoặc module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Xác minh và nhập.** Xác nhận các tên được đề xuất dựa trên quan hệ gọi, constant, string và side effect, sau đó nhập báo cáo JSON bằng plugin GoResolver cho IDA hoặc Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Cài đặt toolchain rồi chạy extractor và graph matcher kết hợp:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

Ngưỡng khớp đáng kể mặc định là `0.9`. Các tùy chọn `--extract` và `--graph` có thể chạy riêng từng giai đoạn, trong khi mặc định chạy cả hai vì metadata runtime được khôi phục và bằng chứng CFG bổ trợ cho nhau.<sup>[[10]](#references)</sup> Điểm CFG mang tính heuristic: inlining, cờ build, kiến trúc và khác biệt phiên bản thư viện có thể làm thay đổi cấu trúc đồ thị, vì vậy hãy giữ lại các hàm chưa xác định thay vì gán tên với độ tin cậy thấp.<sup>[[13]](#references)</sup>

### Khôi phục bảng chuỗi Go

Các binary Go đặt byte chuỗi từ mọi package được liên kết vào một bảng liên tục. Các mục không kết thúc bằng NUL và cấu trúc runtime không cung cấp base hoặc kích thước của bảng. Tuy nhiên, compiler sắp xếp các mục theo độ dài trước, rồi theo thứ tự alphabet trên các hệ điều hành và kiến trúc. Vì vậy, sau khi tìm được một mục, analyst có thể lần theo các mục liền kề và dùng cross-reference dữ liệu để liên kết chuỗi với code.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) tự động hóa quy trình này trong IDA Pro và Ghidra. Trước tiên, hãy để auto-analysis hoàn tất vì plugin dựa vào cross-reference của data segment. Anchor mặc định là chuỗi runtime `entersyscall`; sau đó, công cụ có thể quét theo cả hai hướng, định nghĩa các chuỗi đã khôi phục trong database và xuất mapping JSON giữa chuỗi với các hàm tham chiếu đến chúng.<sup>[[14]](#references)</sup>

Lọc báo cáo theo package của hàm tham chiếu để tách code ứng dụng hoặc malware khỏi dữ liệu nhiễu từ các thư viện được liên kết. Kỹ thuật này không thể khôi phục các literal bị phá hủy bởi quá trình obfuscation như phép biến đổi `-literals` của Garble. Tuy vậy, nó vẫn có thể sắp xếp các chuỗi runtime còn không bị obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Khôi phục kiểu runtime của Go

Go nhúng thông tin kiểu runtime được dùng bởi các tính năng như garbage collection. Khi thông tin build bị loại bỏ hoặc disassembler không phân tích metadata này, các instruction có thể trông như đang tải những địa chỉ dữ liệu tùy ý và vùng đích vẫn chưa được định kiểu. Khôi phục metadata sẽ biến các địa chỉ đó thành tham chiếu kiểu dễ đọc và giúp hiểu rõ hơn các khả năng của package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) có thể trích xuất symbol và phân tích kiểu runtime thành báo cáo JSON. CLI hiện tại dùng subcommand `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Tùy chọn `-y`/`--types` bật tính năng phân tích kiểu. Nhập báo cáo bằng plugin IDA Pro hoặc Ghidra của GoResolver để định nghĩa các kiểu đã khôi phục và áp dụng các tham chiếu của chúng trong cơ sở dữ liệu phân tích. Trong định dạng báo cáo được giới thiệu cùng tính năng này, nếu bỏ qua `-y`, các thành viên địa chỉ RTTI và kiểu đã khôi phục sẽ có giá trị null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver hỗ trợ các mẫu PE, ELF và Mach-O cho x86, AMD64, ARM và ARM64, vì vậy cùng quy trình này áp dụng được cho các binary Go trên Windows, Linux và macOS.<sup>[[10]](#references)</sup>

## Python đã biên dịch

Trong trang này, bạn có thể tìm hiểu cách lấy mã python từ một binary Python đã biên dịch ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Nếu có **binary** của một game GBA, bạn có thể dùng nhiều công cụ khác nhau để **emulate** và **debug** game:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Tải bản debug_) - Có debugger với giao diện
- [**mgba** ](https://mgba.io)- Có CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Trong [**no$gba**](https://problemkaputt.de/gba.htm), tại _**Options --> Emulation Setup --> Controls**_** **, bạn có thể xem cách nhấn các **nút** của Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Khi được nhấn, mỗi **phím có một giá trị** để nhận diện:

```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```

Vì vậy, trong loại chương trình này, phần đáng chú ý là **cách chương trình xử lý dữ liệu đầu vào của người dùng**. Tại địa chỉ **0x4000130**, bạn sẽ tìm thấy hàm thường gặp: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

Trong hình trước, bạn có thể thấy hàm được gọi từ **FUN_080015a8** (các địa chỉ: _0x080015fa_ và _0x080017ac_).

Trong hàm đó, sau một số thao tác khởi tạo (không quan trọng):

```c
void FUN_080015a8(void)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  ushort uVar4;
  int iVar5;
  ushort *puVar6;
  undefined *local_2c;

  DISPCNT = 0x1140;
  FUN_08000a74();
  FUN_08000ce4(1);
  DISPCNT = 0x404;
  FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
  FUN_08000354(&DAT_030000dc,0x3c);
  uVar4 = DAT_030004d8;
```

Tìm thấy đoạn mã này:

```c
  do {
    DAT_030004da = uVar4; //This is the last key pressed
    DAT_030004d8 = KEYINPUT | 0xfc00;
    puVar6 = &DAT_0200b03c;
    uVar4 = DAT_030004d8;
    do {
      uVar2 = DAT_030004dc;
      uVar1 = *puVar6;
      if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```

Điều kiện if cuối cùng kiểm tra xem **`uVar4`** có nằm trong **danh sách phím trước đó** và không phải là phím hiện tại hay không; đây cũng được gọi là nhả một nút (phím hiện tại được lưu trong **`uVar1`**).

```c
        if (uVar1 == 4) {
          DAT_030000d4 = 0;
          uVar3 = FUN_08001c24(DAT_030004dc);
          FUN_08001868(uVar2,0,uVar3);
          DAT_05000000 = 0x1483;
          FUN_08001844(&DAT_0200ba18);
          FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
          DAT_030000d8 = 0;
          uVar4 = DAT_030004d8;
        }
        else {
          if (uVar1 == 8) {
            if (DAT_030000d8 == 0xf3) {
              DISPCNT = 0x404;
              FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
              FUN_08000354(&DAT_030000dc,0x3c);
              uVar4 = DAT_030004d8;
            }
          }
          else {
            if (DAT_030000d4 < 8) {
              DAT_030000d4 = DAT_030000d4 + 1;
              FUN_08000864();
              if (uVar1 == 0x10) {
                DAT_030000d8 = DAT_030000d8 + 0x3a;
```

Trong đoạn code trước, bạn có thể thấy chúng ta đang so sánh **uVar1** (nơi lưu **giá trị của nút được nhấn**) với một số giá trị:

- Đầu tiên, nó được so sánh với **giá trị 4** (nút **SELECT**): Trong thử thách này, nút đó xóa màn hình
- Sau đó, giá trị được so sánh với **8** (nút **START**); trong thử thách này, nhánh đó kiểm tra xem mã đã nhập có hợp lệ hay không.
  - Trong trường hợp này, biến **`DAT_030000d8`** được so sánh với 0xf3 và nếu giá trị trùng khớp thì một đoạn code sẽ được thực thi.
- Trong mọi trường hợp khác, một bộ đếm (`DAT_030000d4`) được kiểm tra và tăng lên.\
  Khi bộ đếm nhỏ hơn 8, các giá trị của những phím được nhấn sẽ được cộng dồn vào `DAT_030000d8`.

Vì vậy, trong thử thách này, khi biết giá trị của các nút, bạn cần **nhấn một tổ hợp có độ dài nhỏ hơn 8 sao cho tổng các giá trị bằng 0xf3.**

**Tài liệu tham khảo cho hướng dẫn này:** [bài viết hướng dẫn giải thử thách Nostalgia đã lưu trữ](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Khóa học

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Đơn giản hóa kỹ thuật làm rối MBA với CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Kho lưu trữ Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Giải mã chuỗi Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - chuỗi Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - hướng dẫn reversing GBA (đã lưu trữ)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Đánh bại kỹ thuật reverse engineering có AI hỗ trợ, hoặc ít nhất là cố gắng](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Một phương pháp so sánh đồ thị luồng điều khiển dựa trên việc so khớp basic block](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Kho lưu trữ Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Cơ chế làm rối Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Sử dụng độ tương đồng của đồ thị luồng điều khiển để tự động gỡ làm rối các binary Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Kho lưu trữ Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Các bản cập nhật cho bộ công cụ Golang của Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [Phân tích mã managed của REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Hướng dẫn CLI và Evidence của REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Quy trình làm phẳng luồng điều khiển trong Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Xâm nhập PaperCut MF Zero-Day, Java Loader, Web Shell và AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README của IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Triển khai máy chủ bridge IDA](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Triển khai máy chủ bridge Ghidra](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) liên kết với địa chỉ wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
