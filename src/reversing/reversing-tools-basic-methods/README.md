# Công cụ phân tích ngược & các phương pháp cơ bản

{{#include ../../banners/hacktricks-training.md}}

## Công cụ phân tích ngược dựa trên ImGui

Phần mềm:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Tự động hóa WinDbg ở chế độ user-mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Phân tích macro trong tài liệu Office

Với các tài liệu Office đáng ngờ, hãy kiểm tra [mã rác trong macro VBA và các điều khiển UserForm ẩn](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

## Luồng điều khiển dựa trên ngoại lệ trong Windows

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Gỡ lỗi kernel Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Trình dịch ngược Wasm / Trình biên dịch Wat

Trực tuyến:

- Dùng [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) để **dịch ngược** từ wasm (nhị phân) sang wat (văn bản dễ đọc)
- Dùng [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) để **biên dịch** từ wat sang wasm
- Bạn cũng có thể thử [web-wasmdec](https://wwwg.github.io/web-wasmdec/) để dịch ngược.

Phần mềm:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode đã lưu trong bộ nhớ đệm của Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payload ảo hóa và VM tùy chỉnh

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Trình dịch ngược .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek là một trình dịch ngược có khả năng **dịch ngược và kiểm tra nhiều định dạng**, bao gồm **thư viện** (.dll), **tệp metadata của Windows** (.winmd) và **tệp thực thi** (.exe). Sau khi dịch ngược, assembly có thể được lưu dưới dạng dự án Visual Studio (.csproj).

Điểm hữu ích ở đây là nếu cần khôi phục mã nguồn đã mất từ một assembly cũ, thao tác này có thể tiết kiệm thời gian. Ngoài ra, dotPeek cung cấp các tính năng điều hướng thuận tiện trong mã đã dịch ngược, khiến nó trở thành một trong những công cụ lý tưởng để **phân tích thuật toán Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Với mô hình add-in toàn diện và API có thể mở rộng công cụ để đáp ứng chính xác nhu cầu của bạn, .NET Reflector giúp tiết kiệm thời gian và đơn giản hóa quá trình phát triển. Hãy cùng xem qua nhiều dịch vụ reverse engineering mà công cụ này cung cấp:

- Cho biết dữ liệu luân chuyển như thế nào qua một thư viện hoặc thành phần
- Cung cấp thông tin về cách triển khai và sử dụng các ngôn ngữ và framework .NET
- Tìm các chức năng chưa được ghi chép và chưa được công khai để khai thác tối đa các API và công nghệ đang sử dụng.
- Tìm các dependency và assembly khác nhau
- Xác định chính xác vị trí lỗi trong mã của bạn, các thành phần bên thứ ba và thư viện.
- Gỡ lỗi đến tận mã nguồn của mọi đoạn mã .NET bạn làm việc cùng.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy cho Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Bạn có thể sử dụng trên mọi OS (có thể cài trực tiếp từ VSCode, không cần tải git. Nhấp vào **Extensions** rồi **tìm ILSpy**).\
Nếu cần **dịch ngược**, **chỉnh sửa** và **biên dịch lại**, bạn có thể dùng [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) hoặc một fork được duy trì tích cực của công cụ này là [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Nhấp chuột phải -> Modify Method** để thay đổi nội dung bên trong một hàm).

### Kiểm tra assembly managed mà không thực thi bằng REA

**REA** có thể kiểm tra metadata PE/CLI và CIL mà không cần tải assembly. Hãy bắt đầu bằng cách xác định danh tính của artifact, sau đó kiểm tra các thành viên và ranh giới native đã khai báo; cách này hữu ích khi xem xét các lệnh gọi đáng ngờ trước khi dùng trình dịch ngược hoặc chạy chương trình.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Để so sánh diff giữa các phiên bản, `compare_managed_members` sử dụng danh tính CIL/chữ ký thô và fingerprint của các lệnh đã giải mã, thay vì xem metadata token là ổn định giữa các lần build. Một khai báo P/Invoke không chứng minh rằng mã native đã chạy; `verify_managed_native_boundaries` cần export native hoặc Evidence của hàm tương ứng để kiểm tra ranh giới đó. Hãy giữ digest của artifact, MVID và các ánh xạ chưa phân giải cùng với kết quả.<sup>[[17]](#references)</sup>

### Ghi nhật ký DNSpy

Để **DNSpy ghi một số thông tin vào tệp**, bạn có thể dùng đoạn mã này:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Gỡ lỗi bằng DNSpy

Để gỡ lỗi mã bằng DNSpy, bạn cần:

Trước tiên, thay đổi **các thuộc tính Assembly** liên quan đến **gỡ lỗi**:

![Ghi log bằng DNSpy - Gỡ lỗi bằng DNSpy: Trước tiên, thay đổi các thuộc tính Assembly liên quan đến gỡ lỗi](<../../images/image (973).png>)

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

Và nhấn **compile**:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Sau đó lưu tệp mới bằng _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Việc này là cần thiết vì nếu không, ở **thời gian chạy**, một số **tối ưu hóa** sẽ được áp dụng cho mã và có thể xảy ra trường hợp khi gỡ lỗi, **điểm dừng không bao giờ được kích hoạt** hoặc một số **biến không tồn tại**.

Sau đó, nếu ứng dụng .NET của bạn đang được **chạy** bởi **IIS**, bạn có thể **khởi động lại** bằng:

```
iisreset /noforce
```

Sau đó, để bắt đầu debugging, bạn nên đóng tất cả các file đang mở và trong **Debug Tab** chọn **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Sau đó, để bắt đầu debugging, bạn nên đóng tất cả các file đang mở và trong Debug Tab chọn Attach to Process](<../../images/image (318).png>)

Sau đó chọn **w3wp.exe** để attach vào **IIS server** rồi nhấp **attach**:

![DNSpy Logging - DNSpy Debugging: Sau đó chọn w3wp.exe để attach vào IIS server rồi nhấp attach](<../../images/image (113).png>)

Giờ đây chúng ta đang debugging process, đã đến lúc dừng process và tải tất cả các module. Trước tiên, nhấp vào _Debug >> Break All_, sau đó nhấp vào _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Giờ đây chúng ta đang debugging process, đã đến lúc dừng process và tải tất cả các module. Trước tiên, nhấp vào Debug Break All, sau đó nhấp vào Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Giờ đây chúng ta đang debugging process, đã đến lúc dừng process và tải tất cả các module. Trước tiên, nhấp vào Debug Break All, sau đó nhấp vào Debug Windows Modules](<../../images/image (834).png>)

Nhấp vào một module bất kỳ trong **Modules** rồi chọn **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Nhấp vào một module bất kỳ trong Modules rồi chọn Open All Modules](<../../images/image (922).png>)

Nhấp chuột phải vào một module bất kỳ trong **Assembly Explorer** rồi nhấp **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Nhấp chuột phải vào một module bất kỳ trong Assembly Explorer rồi nhấp Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Sử dụng IDA

- **Load rundll32** (64bits trong C:\Windows\System32\rundll32.exe và 32 bits trong C:\Windows\SysWOW64\rundll32.exe)
- Chọn debugger **Windbg**
- Chọn "**Suspend on library load/unload**"

![Debugging DLLs - Sử dụng IDA: Chọn " Suspend on library load/unload "](<../../images/image (868).png>)

- Cấu hình **parameters** cho quá trình thực thi bằng cách nhập **path đến DLL** và function bạn muốn gọi:

![Debugging DLLs - Sử dụng IDA: Cấu hình parameters cho quá trình thực thi bằng cách nhập path đến DLL và function bạn muốn gọi](<../../images/image (704).png>)

Sau đó, khi bắt đầu debugging, **quá trình thực thi sẽ dừng mỗi khi DLL được load**; khi rundll32 load DLL của bạn, quá trình thực thi sẽ dừng lại.

Phương pháp này dừng tại các sự kiện module-load, nhưng việc đến entry point của DLL đã load không trực tiếp bằng quy trình x64dbg bên dưới.

### Sử dụng x64dbg/x32dbg

- **Load rundll32** (64bits trong C:\Windows\System32\rundll32.exe và 32 bits trong C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) và đặt path của dll cùng function bạn muốn gọi, ví dụ: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Thay đổi _Options --> Settings_ rồi chọn "**DLL Entry**".
- Sau đó **bắt đầu thực thi**; debugger sẽ dừng tại từng dll main. Đến một thời điểm, bạn sẽ **dừng tại dll Entry của DLL mình**. Từ đó, hãy tìm các vị trí bạn muốn đặt breakpoint.

Lưu ý rằng khi quá trình thực thi dừng vì bất kỳ lý do nào trong win64dbg, bạn có thể xem **đoạn code hiện tại** ở **phía trên cùng cửa sổ win64dbg**:

![Sử dụng IDA - Sử dụng x64dbg/x32dbg: Lưu ý rằng khi quá trình thực thi dừng vì bất kỳ lý do nào trong win64dbg, bạn có thể xem đoạn code hiện tại ở phía trên cùng cửa sổ win64dbg](<../../images/image (842).png>)

Chỉ báo này xác nhận quá trình thực thi đã dừng bên trong DLL bạn muốn debug.

## Ứng dụng GUI / Trò chơi điện tử

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) là chương trình hữu ích để tìm vị trí lưu các giá trị quan trọng trong bộ nhớ của một trò chơi đang chạy và thay đổi chúng. Xem thêm thông tin tại:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) là công cụ front-end/reverse engineering dành cho GNU Project Debugger (GDB), tập trung vào trò chơi. Tuy nhiên, công cụ này có thể dùng cho mọi tác vụ liên quan đến reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) là front-end trên web cho nhiều decompiler. Dịch vụ web này cho phép bạn so sánh kết quả của các decompiler khác nhau trên những executable nhỏ.

### Giải mã PCK Godot và khôi phục project

Đối với trò chơi Godot được phân phối, hãy tìm PCK của trò chơi trong file `.pck` độc lập, pack được nối vào hoặc nhúng trong executable, hoặc thư mục `assets` của APK. [gore](https://github.com/figurophobia/gore) có thể kiểm tra và trích xuất pack, trong khi việc khôi phục đầy đủ script và resource cần GDRE Tools (`gore setup` cài đặt công cụ này, hoặc dùng `--gdre`). Công cụ hỗ trợ các định dạng PCK Godot 4.x v2–v4 cho quy trình này; công cụ có thể nhận diện header v1 nhưng cần cung cấp key cho v1.<sup>[[25]](#references)</sup>

Tự động khôi phục key cần có file table được mã hóa; nếu chỉ nội dung file được mã hóa, hãy cung cấp key đã biết. Khôi phục thất bại không chứng minh pack không được mã hóa.<sup>[[28]](#references)</sup>

Việc tìm kiếm key **không** phải là tấn công vét cạn keyspace AES-256. File table được mã hóa sẽ để lộ MD5 của bản rõ, độ dài bản rõ, IV và ciphertext AES-256-CFB.<sup>[[27]](#references)</sup> `gore` kiểm tra các cửa sổ 32 byte trong executable của trò chơi hoặc các file lân cận để tìm key ứng viên. Công cụ lọc ứng viên dựa trên độ dài và tiền tố đường dẫn đã giải mã có vẻ hợp lệ, sau đó xác nhận các kết quả tìm được qua quét nhị phân bằng cách giải mã toàn bộ table và kiểm tra MD5 của nó.<sup>[[26]](#references)[[28]](#references)</sup> Công cụ tìm trong các section dữ liệu đã khởi tạo của PE/ELF trước, rồi chuyển sang quét toàn bộ file; `--scan` bổ sung các file ứng viên khác.<sup>[[28]](#references)</sup>

Nếu không tìm thấy key nhúng, công cụ sẽ thử một danh sách mật khẩu nhỏ có sẵn; `--wordlist` dùng để cung cấp các ứng viên khác. Mỗi mật khẩu được thử dưới dạng biểu diễn key do engine tạo từ mật khẩu, chuỗi literal được đệm bằng số 0 hoặc key gồm 64 ký tự hex. Khác với các kết quả tìm được qua quét nhị phân, kết quả từ wordlist trong phiên bản này chỉ vượt qua bước lọc cấu trúc đường dẫn. Hãy xác nhận chúng bằng cách mở pack và kiểm tra các asset đã trích xuất.<sup>[[26]](#references)[[28]](#references)</sup>

Khi có artifact của trò chơi trên máy cục bộ, hãy chọn bước phù hợp với nhu cầu phân tích. `recover` gọi GDRE để khôi phục một project có thể mở, còn `extract` chỉ giải nén các file thô. `key` in ra key ứng viên để dùng với công cụ khác.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Điều tra native dựa trên bằng chứng với REA

**REA** cung cấp khả năng phân tích Hopper, Ghidra và IDA qua CLI và MCP. Công cụ yêu cầu Node.js 22.x (ít nhất 22.19), 24.x (ít nhất 24.11) hoặc 26+, cùng với npm. Trước tiên, hãy cấu hình một native provider hiện có; kiểm tra `rea providers --json` và chọn rõ provider khi có nhiều provider hỗ trợ target. Thay `0x1000` bên dưới bằng tên hàm hoặc địa chỉ đã quan sát được trong inventory.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Bắt đầu từ một chuỗi đặc trưng hoặc symbol, lần theo các tham chiếu và caller, sau đó kiểm tra hồ sơ dossier của function đã chọn và pseudocode bằng `rea decompile`. REA gắn session với provider đã chọn thay vì âm thầm thay thế provider sau khi gặp lỗi. Để có thể lặp lại truy vấn, `--snapshot PATH` chỉ dùng lại các byte artifact, provider, settings, operation và parameters trùng khớp; snapshot là cache cục bộ, không phải cơ sở dữ liệu provider đã lưu. Hãy giữ nguyên Evidence được trả về và những thông tin chưa biết được nêu rõ, thay vì xem các đường dẫn suy luận hoặc văn bản decompiler là source gốc.<sup>[[16]](#references)[[18]](#references)</sup>

Để xem các entry point JavaScript/Electron dẫn vào native add-on, xem [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Phân tích IDA và Ghidra bằng script với cầu nối TCP cục bộ

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) chạy bên trong cơ sở dữ liệu IDA hoặc chương trình Ghidra CodeBrowser **đang mở** và cho phép một script riêng truy vấn, chỉnh sửa cơ sở dữ liệu phân tích đó. Chạy `ID_Server.py` từ Python CLI của IDA (`import ID_Server`) hoặc `Ghidra_Server.py` từ Script Manager của Ghidra. IDA bind vào `127.0.0.1`, bắt đầu từ port `5073` và quét các port cao hơn. Script Ghidra hiện tại bắt đầu từ port `5093` và thử mười port đến `5102`; socket Java của nó bind vào địa chỉ wildcard, không chỉ loopback. Hãy kiểm tra port được instance in ra trước khi kết nối. Khác với headless analyzer, cầu nối này hoạt động trên chương trình hiện đang mở trong instance GUI đó.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Gửi **mỗi kết nối một command kết thúc bằng newline** và đọc response kết thúc bằng newline. Kết quả thường ở dạng JSON. Ví dụ, sau khi tìm thấy một API được import có liên quan đến đường dẫn đầu vào, `IMPORTXREF` tìm các call site của API đó; tiếp theo, `DECOMP_XREF` decompile hàng loạt các caller của địa chỉ đã chọn. `FUNC` kiểm tra một function, còn `PCODE` trả về biểu diễn trung gian của decompiler. Hãy dùng địa chỉ từ cơ sở dữ liệu đang hoạt động, không dùng địa chỉ được sao chép từ một binary đã rebase khác. Ví dụ dưới đây dùng port mặc định của IDA; với Ghidra, hãy dùng port được script in ra.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Cùng một channel có thể **thay đổi database phân tích**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` và `PATCH` sửa đổi tên, kiểu, định nghĩa cấu trúc, ranh giới hàm hoặc byte được lưu trữ. `PATCH` là một chỉnh sửa database, **không phải** bằng chứng về việc patch tiến trình đang chạy. Không listener nào có tài liệu về xác thực. IDA chỉ lắng nghe trên loopback, nhưng Ghidra có thể truy cập qua các network interface; hãy hạn chế quyền truy cập vào listener của Ghidra khi sử dụng. `QUIT` dừng một trong hai listener, và IDA cũng cung cấp `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debug shellcode bằng blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) cấp phát **shellcode**, in ra **địa chỉ bộ nhớ** của nó và tạm dừng quá trình thực thi.\
Gắn debugger như IDA hoặc x64dbg, đặt breakpoint tại địa chỉ được in ra, rồi tiếp tục thực thi để debug shellcode.

Trang GitHub releases có các tệp zip chứa những bản đã biên dịch: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Bạn có thể tìm thấy một phiên bản Blobrunner đã được chỉnh sửa đôi chút tại liên kết sau. Để biên dịch, chỉ cần **tạo một project C/C++ trong Visual Studio Code, sao chép và dán code rồi build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debug shellcode bằng jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) tương tự BlobRunner. Công cụ này cấp phát shellcode rồi đi vào một vòng lặp vô hạn. Gắn debugger, tiếp tục thực thi trong **2–5 giây**, tạm dừng bên trong vòng lặp đó, rồi step đến lệnh gọi tiếp theo chuyển quyền thực thi sang shellcode đã được cấp phát.

![Debugger tạm dừng trong vòng lặp vô hạn của jmp2it ngay trước lệnh gọi shellcode đã được cấp phát](<../../images/image (509).png>)

Bạn có thể tải phiên bản đã biên dịch của [jmp2it tại trang releases](https://github.com/adamkramer/jmp2it/releases/).

### Debug shellcode bằng Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) là GUI của radare. Dùng Cutter, bạn có thể mô phỏng shellcode và kiểm tra nó khi chạy.

Lưu ý rằng Cutter cho phép bạn chọn "Open File" và "Open Shellcode". Trong trường hợp của tôi, khi mở shellcode dưới dạng file, công cụ decompile chính xác, nhưng khi mở dưới dạng shellcode thì không:

![Cutter hiển thị kết quả phân tích khác nhau khi mở cùng một dãy byte dưới dạng file hoặc shellcode](<../../images/image (562).png>)

Để bắt đầu mô phỏng tại vị trí mong muốn, hãy đặt bp ở đó; có vẻ Cutter sẽ tự động bắt đầu mô phỏng từ vị trí đó:

![Đặt breakpoint tại điểm vào shellcode mong muốn trước khi bắt đầu mô phỏng bằng Cutter](<../../images/image (589).png>)

![Trình mô phỏng của Cutter tạm dừng tại breakpoint shellcode đã chọn](<../../images/image (387).png>)

Ví dụ, bạn có thể xem stack trong một hex dump:

![Xem stack shellcode được mô phỏng trong hex dump của Cutter](<../../images/image (186).png>)

### Deobfuscate shellcode và tìm các hàm được thực thi

Bạn nên thử [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Công cụ này sẽ cho bạn biết những thông tin như shellcode đang sử dụng **những hàm nào** và liệu shellcode có đang **giải mã** chính nó trong bộ nhớ hay không.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg cũng có một trình khởi chạy đồ họa, nơi bạn có thể chọn các tùy chọn mong muốn và thực thi shellcode

![Trình khởi chạy đồ họa của scDbg để chọn các tùy chọn mô phỏng và theo dõi shellcode](<../../images/image (258).png>)

Tùy chọn **Create Dump** sẽ dump shellcode cuối cùng nếu shellcode bị thay đổi động trong bộ nhớ (hữu ích để tải xuống shellcode đã giải mã). **start offset** có thể hữu ích khi cần bắt đầu chạy shellcode tại một offset cụ thể. Tùy chọn **Debug Shell** hữu ích để debug shellcode bằng terminal của scDbg (tuy nhiên, tôi thấy các tùy chọn đã giải thích trước đó phù hợp hơn vì bạn có thể dùng Ida hoặc x64dbg).

### Disassemble bằng CyberChef

Tải tệp shellcode lên làm đầu vào và dùng recipe sau để dịch ngược nó: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation che giấu các biểu thức đơn giản như `x + y` bằng những công thức kết hợp phép toán số học (`+`, `-`, `*`) và toán tử bitwise (`&`, `|`, `^`, `~`, phép dịch bit). Điểm quan trọng là các đồng nhất thức này thường chỉ đúng trong **phép toán modulo với độ rộng cố định**, vì vậy cần lưu ý đến bit nhớ và hiện tượng tràn số:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Nếu đơn giản hóa biểu thức dạng này bằng các công cụ đại số tổng quát, bạn có thể dễ dàng nhận được kết quả sai vì đã bỏ qua ngữ nghĩa độ rộng bit.<sup>[[1]](#references)</sup>

### Quy trình thực tế

1. **Giữ nguyên độ rộng bit ban đầu** từ mã/IR đã nâng cấp hoặc đầu ra của decompiler (`8/16/32/64` bit).
2. **Phân loại biểu thức** trước khi thử đơn giản hóa:
   - **Tuyến tính**: tổng có trọng số của các phần tử bitwise
   - **Bán tuyến tính**: biểu thức tuyến tính cộng với các mask hằng như `x & 0xFF`
   - **Đa thức**: có phép nhân
   - **Hỗn hợp**: phép nhân và logic bitwise đan xen, thường có các biểu thức con lặp lại
3. **Xác minh mọi phép biến đổi ứng viên** bằng kiểm thử ngẫu nhiên hoặc chứng minh SMT. Nếu không thể chứng minh tính tương đương, hãy giữ nguyên biểu thức ban đầu thay vì đoán.

### Vượt qua control-flow flattening bằng một lát cắt thực thi hẹp

Thường không cần khôi phục toàn bộ đồ thị luồng điều khiển. Khi gặp control-flow flattening, opaque predicates, dispatcher lớn hoặc mã nặng MBA, hãy lần theo các tham chiếu từ blob được mã hóa và buffer đầu ra đến routine nhỏ nhất có nhiệm vụ biến đổi chúng. Sau đó, chỉ tái tạo lát cắt luồng dữ liệu đó hoặc thực thi nó độc lập; dispatcher không phải là một phần của lời giải cần thiết nếu có thể khởi tạo trực tiếp trạng thái liên quan.<sup>[[7]](#references)</sup>

Quy trình thực tế:<sup>[[7]](#references)</sup>

1. Kiểm kê các section thực thi và dữ liệu, relocation và tham chiếu chéo. Trích xuất các bảng ứng viên từ `.rodata`, đồng thời giữ nguyên thứ tự byte và độ rộng phần tử.
2. Xác định routine cuối cùng ghi plaintext hoặc buffer đầu ra. Ghi lại đầu vào, các bảng được tham chiếu, lời gọi đã import và trạng thái toàn cục cần thiết.
3. Chỉ nâng các thao tác đó thành mô hình Python có độ rộng cố định. Nếu lát cắt vẫn phụ thuộc vào quá nhiều trạng thái, hãy gọi routine bằng Unicorn, QEMU hoặc debugger và hook các import không liên quan thay vì mô phỏng toàn bộ chương trình.
4. Xác thực rằng extractor thực sự tạo đầu ra từ binary được cung cấp: loại bỏ các fallback âm thầm, tìm kiếm đáp án được nhúng trong binary, và chạy extractor trên các bản build chưa từng thấy với chuỗi, key, identifier, layout và seed obfuscation đã thay đổi.

Một số lệnh hữu ích để kiểm tra sơ bộ:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Phát hiện các biểu thức MBA ngụy trang thành hằng số

Một biểu thức byte có vẻ phụ thuộc vào đầu vào có thể triệt tiêu hoàn toàn đầu vào đó. Sau khi trích xuất các bảng, hãy tính giá trị biểu thức trên toàn bộ miền 8 bit; nếu tập đầu ra chỉ có một giá trị, điều đó chứng minh byte ấy là hằng số mà không cần khôi phục máy trạng thái xung quanh.<sup>[[7]](#references)</sup>

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

Giữ lại mask cuối cùng vì phép cộng ban đầu có hiện tượng wraparound theo độ rộng byte. Với miền rộng hơn, hãy hỏi SMT solver liệu `f(x1) != f(x2)` có thỏa mãn được với hai đầu vào ký hiệu cùng độ rộng hay không: `unsat` chứng minh tính bất biến, còn `sat` đưa ra một phản ví dụ và nghĩa là không thể loại bỏ đầu vào đó.<sup>[[7]](#references)</sup>

#### Nhận diện giải mã phụ thuộc môi trường

Các kiểm tra anti-analysis không nhất thiết phải rẽ nhánh hoặc gây crash. Bộ giải mã có thể trộn kết quả cảm biến vào một bit khóa, hằng số opaque predicate hoặc trạng thái flattened dispatcher, tiếp tục chạy bình thường và tạo ra plaintext trông có vẻ hợp lý nhưng sai trong emulator. Vì vậy, chỉ patch các nhánh lỗi hiển thị là chưa đủ; hãy truy vết các phụ thuộc dữ liệu từ các phép thăm dò môi trường đến trạng thái bộ giải mã, so sánh cùng một đoạn trên thiết bị thật và emulator, rồi kiểm tra việc ép từng kết quả cảm biến sẽ thay đổi buffer cuối cùng như thế nào.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) là công cụ đơn giản hóa MBA thiết thực để phân tích malware và reverse binary được bảo vệ. Công cụ phân loại biểu thức rồi chuyển biểu thức qua các pipeline chuyên biệt, thay vì áp dụng một lượt viết lại chung cho mọi thứ.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA đánh giá biểu thức trên các đầu vào Boolean, suy ra chữ ký và thử đồng thời nhiều phương pháp khôi phục như pattern matching, chuyển đổi ANF và nội suy hệ số.
- **Semilinear MBA**: Các atom được mask bằng hằng số được dựng lại bằng phương pháp tái tạo phân vùng theo bit để các vùng được mask vẫn chính xác.
- **Polynomial/Mixed MBA**: Các tích được phân rã thành các lõi, và các biểu thức con lặp lại có thể được đưa vào biến tạm trước khi đơn giản hóa quan hệ bên ngoài.

Ví dụ về một đồng nhất thức mixed thường đáng thử khôi phục:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Điều này có thể rút gọn thành:

```c
x * y
```

### Ghi chú về reverse engineering

- Ưu tiên chạy CoBRA trên **các biểu thức IR đã lift** hoặc đầu ra decompiler sau khi đã cô lập phép tính chính xác.
- Dùng `--bitwidth` một cách tường minh khi biểu thức bắt nguồn từ phép toán có mask hoặc thanh ghi hẹp.
- Nếu cần bước chứng minh mạnh hơn, hãy xem ghi chú Z3 tại đây:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA cũng được cung cấp dưới dạng **plugin LLVM pass** (`libCobraPass.so`), hữu ích khi bạn muốn chuẩn hóa LLVM IR chứa nhiều MBA trước các pass phân tích tiếp theo.
- Các phần dư hỗn hợp miền nhạy với carry nhưng không được hỗ trợ nên được xem là dấu hiệu cần giữ nguyên biểu thức ban đầu và phân tích thủ công đường đi của carry.

## Khôi phục control-flow flattening bằng trạng thái XOR

Một flattener kiểu OLLVM có thể lưu trạng thái basic block hiện tại trong hai thanh ghi 64-bit và khôi phục trạng thái bằng XOR tại dispatcher. Mỗi block gốc ghi cặp giá trị tương ứng với trạng thái kế tiếp rồi nhảy về dispatcher. Một block có điều kiện có thể dùng `CMOVcc` để thay thế một nửa của cặp theo các cờ CPU, vì vậy nếu chỉ lần theo các lệnh nhánh hiển thị thì sẽ bỏ sót một trong hai successor. Không giống dispatcher dùng indirect jump, dạng này có thể chỉ sử dụng các back-edge trực tiếp.<sup>[[19]](#references)[[20]](#references)</sup>

Để khôi phục graph, hãy xác định cây so sánh của dispatcher và hai thanh ghi trạng thái, ánh xạ từng trạng thái XOR được so sánh tới block đích, rồi lần theo các lệnh ghi vào cặp thanh ghi trong mỗi block gốc. Với các lệnh ghi có điều kiện, hãy tính đến lệnh thiết lập cờ và cả hai kết quả `CMOVcc`. Viết lại lối ra dispatcher của mỗi block thành successor trực tiếp đã xác định hoặc nhánh có điều kiện; khi đó dispatcher sẽ không còn reachable mà không cần patch binary. Đây là phương pháp tiếp cận toàn bộ CFG; nếu chỉ cần một decoder, quy trình [narrow execution-slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) ở trên có thể nhanh hơn.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) tự động hóa dạng này trong Binary Ninja. Sao chép `plugins/DispatchThis` vào thư mục plugin người dùng của Binary Ninja rồi khởi động lại. Trên function bị ảnh hưởng, mở **Function Settings** và chọn `OLLVM_XOR_64`; nếu phân tích không bắt đầu, hãy dùng **Analysis → Reanalyze All Functions**. Chế độ này viết lại các cạnh control-flow của MLIL, không sửa byte trong file và không cần Z3 hay indirect-jump resolver. Công cụ đã được thử nghiệm trên Binary Ninja 5.3.9757+; nó không xóa các lệnh ghi trạng thái theo block đã chết, vì vậy đừng nhầm chúng với các transition còn hoạt động.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator này thay các thao tác của chương trình bằng các chuỗi lệnh dựa trên `mov` và sử dụng xử lý signal/exception để thay đổi control flow. Tìm hiểu thêm:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Với các binary được hỗ trợ, [demovfuscator](https://github.com/kirschju/demovfuscator) có thể deobfuscate kết quả. Công cụ này có một số dependency.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Và [cài đặt keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Nếu bạn đang chơi **CTF, cách khắc phục này để tìm flag** có thể rất hữu ích: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Để tìm **entry point**, hãy tìm các hàm có tên chứa `::main`, như trong ví dụ:

![Tìm entry point của Rust trong Ghidra bằng cách tìm tên hàm có hai dấu hai chấm trước main](<../../images/image (1080).png>)

Trong trường hợp này, binary có tên là authenticator, nên khá rõ ràng đây là hàm main đáng chú ý.\
Dựa vào **tên** của các **hàm** được gọi, hãy tìm kiếm chúng trên **Internet** để tìm hiểu về **đầu vào** và **đầu ra** của chúng.

### Khôi phục chuỗi Rust từ firmware ELF

Trong các binary **Rust ELF**, nhiều chuỗi tĩnh không được tham chiếu bằng con trỏ kết thúc bằng NUL theo kiểu C. Một bố cục `rustc` phổ biến là một **tuple con trỏ/độ dài** bên trong **`.data.rel.ro`**, trỏ đến vùng chứa chuỗi thực sự được lưu trong **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Điều này có nghĩa là `strings` hoặc phân tích Ghidra mặc định có thể gộp các chuỗi liền kề hoặc bỏ sót hoàn toàn các tham chiếu chéo.<sup>[[3]](#references)</sup>

Quy trình nhanh:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Lấy địa chỉ ảo và kích thước của **`.rodata`**.
2. Liệt kê **`.data.rel.ro`** từng word một.
3. Xem mọi giá trị nằm trong phạm vi địa chỉ của `.rodata` là một con trỏ chuỗi tiềm năng.
4. Xem word tiếp theo là độ dài tiềm năng.
5. Áp dụng các bộ lọc hợp lý (ví dụ: giữ độ dài từ **4** đến **100** byte).
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

Điều này đặc biệt hữu ích khi reversing firmware vì các chuỗi Rust khôi phục được thường tiết lộ **HTTP routes, tên RPC, thông báo log, assertions, tên file, config keys, command handlers và logic liên quan đến auth**.

Nếu Ghidra bỏ sót các chuỗi đó, hãy chạy một script/plugin tùy chỉnh áp dụng cùng heuristic và tạo dữ liệu chuỗi tại các offset `.rodata` được tham chiếu. Các công cụ `rust-strings` và `RustStrings.py` do Pen Test Partners công bố là tài liệu tham khảo hữu ích để điều chỉnh ý tưởng này cho các **word size, endianness và bố cục section khác**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Đối với các binary được biên dịch bằng Delphi, bạn có thể dùng [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Nếu cần reverse một binary Delphi, tôi khuyên bạn nên dùng plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Nhấn **Alt+F7** trong IDA để tải plugin Python, sau đó chọn file plugin.

Plugin này sẽ thực thi binary và phân giải động tên hàm khi bắt đầu debugging. Sau khi bắt đầu debugging, nhấn lại nút Start (nút màu xanh lá hoặc f9) để breakpoint dừng ở đầu phần code thực.

Nếu nhấn một nút trong ứng dụng đồ họa, debugger có thể dừng tại hàm được nút đó gọi.

## Golang

Đối với các binary Go thông thường, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) có thể khôi phục các cấu trúc runtime và cải thiện tên hàm trong IDA. Tải plugin Python bằng **Alt+F7**.

Nếu cần reverse một binary Golang, tôi khuyên bạn nên dùng plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Nhấn **Alt+F7** trong IDA để tải plugin Python, sau đó chọn file plugin.

Plugin này sẽ phân giải tên các hàm.

### Khôi phục metadata mà không cần symbol table

Một file thực thi Go đã bị strip vẫn cần metadata runtime để ánh xạ program counter sang các hàm. [GoReSym](https://github.com/mandiant/GoReSym) tìm và phân tích các cấu trúc như `pclntab` và `moduledata` bằng code được phát triển từ Go runtime. Công cụ này có thể khôi phục ranh giới hàm, tên hàm, đường dẫn mã nguồn, kiểu dữ liệu và thông tin build mà không cần dựa vào symbol table thông thường.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Một obfuscator có thể giữ cho các cấu trúc đó vẫn sử dụng được trong khi thay thế các tên đã khôi phục. Chẳng hạn, Garble băm các identifier và đường dẫn package, đồng thời loại bỏ thông tin build, module và debug.<sup>[[12]](#references)</sup> Token package đã làm rối phải nhất quán giữa các function thuộc package đó. Nhóm các function theo token lặp lại, suy ra một package từ các hàm được gọi, chuỗi và API của chúng, sau đó gán nhãn package đó cho toàn bộ nhóm.<sup>[[13]](#references)</sup>

### Khôi phục tên Garble bằng GoResolver

[GoResolver](https://github.com/volexity/GoResolver) kết hợp trích xuất runtime-symbol với việc tạo tham chiếu sạch và đối sánh control-flow graph (CFG). Thực hiện theo trình tự sau:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Xác định phiên bản compiler.** Trước tiên, hãy thử `BuildInfo` và các chuỗi phiên bản được nhúng. Nếu obfuscator đã xóa chúng, hãy so sánh các phần của Go runtime đi kèm với các runtime tham chiếu có phiên bản. Trong các thử nghiệm của Volexity, khoảng `2%` runtime là đủ để phân biệt các phiên bản Go chính. Hãy xem đây là một tối ưu hóa dựa trên thực nghiệm, không phải ngưỡng áp dụng chung.<sup>[[13]](#references)</sup>
2. **Tạo các tham chiếu phù hợp.** Tạo các binary sạch cho phiên bản Go đã xác định, kiến trúc mục tiêu và các thư viện có khả năng được sử dụng. Khớp toolchain giúp giảm khác biệt CFG do compiler tạo ra.<sup>[[10]](#references)[[13]](#references)</sup>
3. **So sánh các function.** GoGrapher đối sánh CFG của các function và xuất điểm số đã chuẩn hóa từ `0.0` đến `1.0`. Việc đối sánh basic block dựa trên phép so sánh có trọng số giữa các instruction tương tự. Các kết quả khớp có độ tin cậy cao sẽ ánh xạ các function đã được ngẫu nhiên hóa sang phần triển khai sạch. Các kết quả yếu hơn vẫn có thể xác định package hoặc module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Xác thực và nhập.** Xác nhận các tên được đề xuất bằng quan hệ gọi, hằng số, chuỗi và side effect, sau đó nhập báo cáo JSON bằng plugin GoResolver cho IDA hoặc Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Cài đặt toolchain và chạy bộ trích xuất kết hợp với bộ đối sánh đồ thị:<sup>[[10]](#references)</sup>

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

Ngưỡng khớp đáng kể mặc định là `0.9`. Các tùy chọn `--extract` và `--graph` có thể chỉ chạy riêng từng giai đoạn, trong khi mặc định sẽ chạy cả hai vì metadata runtime khôi phục được và bằng chứng CFG bổ trợ cho nhau.<sup>[[10]](#references)</sup> Điểm CFG chỉ mang tính heuristic: inlining, build flags, kiến trúc và khác biệt phiên bản thư viện có thể làm thay đổi cấu trúc đồ thị, vì vậy hãy giữ lại các hàm chưa xác định thay vì gán tên với độ tin cậy thấp.<sup>[[13]](#references)</sup>

### Khôi phục bảng chuỗi Go

Các binary Go đặt byte chuỗi từ mọi package được liên kết vào một bảng liên tục. Các mục không được kết thúc bằng NUL và cấu trúc runtime không cho biết base hoặc kích thước của bảng. Tuy nhiên, compiler sắp xếp các mục trước tiên theo độ dài, sau đó theo thứ tự alphabet trên mọi hệ điều hành và kiến trúc. Vì vậy, sau khi tìm được một mục, analyst có thể duyệt các mục liền kề và dùng tham chiếu chéo dữ liệu để liên kết chuỗi với mã.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) tự động hóa quy trình này trong IDA Pro và Ghidra. Trước tiên, hãy để auto-analysis hoàn tất vì plugin dựa vào tham chiếu chéo trong data segment. Điểm neo mặc định là chuỗi runtime `entersyscall`; sau đó, công cụ có thể quét theo cả hai hướng, định nghĩa các chuỗi đã khôi phục trong database và xuất ánh xạ JSON từ chuỗi đến các hàm tham chiếu tới chúng.<sup>[[14]](#references)</sup>

Lọc báo cáo theo package của hàm tham chiếu để tách mã ứng dụng hoặc malware khỏi nhiễu từ các thư viện được liên kết. Kỹ thuật này không thể khôi phục các literal bị phá hủy bởi obfuscation, chẳng hạn như phép biến đổi `-literals` của Garble. Tuy vậy, nó vẫn có thể sắp xếp các chuỗi runtime còn không bị obfuscate.<sup>[[14]](#references)[[15]](#references)</sup>

### Khôi phục các kiểu runtime của Go

Go nhúng thông tin kiểu runtime được dùng bởi các tính năng như garbage collection. Khi build information bị loại bỏ hoặc disassembler không phân tích metadata này, các lệnh có thể trông như đang tải các địa chỉ dữ liệu bất kỳ và vùng đích vẫn chưa được gán kiểu. Khôi phục metadata sẽ biến các địa chỉ đó thành tham chiếu kiểu dễ đọc và giúp hiểu rõ hơn các khả năng của package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) có thể trích xuất symbols và phân tích các kiểu runtime thành báo cáo JSON. CLI hiện tại sử dụng subcommand `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Tùy chọn `-y`/`--types` bật tính năng phân tích kiểu dữ liệu. Nhập báo cáo bằng plugin IDA Pro hoặc Ghidra của GoResolver để định nghĩa các kiểu dữ liệu đã khôi phục và áp dụng các tham chiếu của chúng trong cơ sở dữ liệu phân tích. Trong định dạng báo cáo được giới thiệu cùng tính năng này, nếu bỏ qua `-y`, các trường địa chỉ RTTI và kiểu dữ liệu đã khôi phục sẽ có giá trị null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver hỗ trợ các mẫu PE, ELF và Mach-O cho x86, AMD64, ARM và ARM64, vì vậy có thể áp dụng cùng quy trình này cho các binary Go trên Windows, Linux và macOS.<sup>[[10]](#references)</sup>

## Python đã biên dịch

Trong trang này, bạn có thể tìm hiểu cách lấy mã Python từ một binary Python được biên dịch thành ELF/EXE:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Nếu có **binary** của một trò chơi GBA, bạn có thể dùng các công cụ khác nhau để **emulate** và **debug** trò chơi đó:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Tải phiên bản debug_) - Có debugger với giao diện
- [**mgba** ](https://mgba.io)- Có debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Trong [**no$gba**](https://problemkaputt.de/gba.htm), tại _**Options --> Emulation Setup --> Controls**_** **, bạn có thể xem cách nhấn các **nút** trên Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Khi nhấn, mỗi **phím có một giá trị** để nhận dạng:

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

Vì vậy, trong loại chương trình này, phần đáng chú ý sẽ là **cách chương trình xử lý dữ liệu đầu vào của người dùng**. Tại địa chỉ **0x4000130**, bạn sẽ tìm thấy hàm thường gặp: **KEYINPUT**.

![Giao diện Ghidra của một binary GBA tham chiếu đến KEYINPUT tại địa chỉ 0x4000130](<../../images/image (447).png>)

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

Điều kiện if cuối cùng kiểm tra xem **`uVar4`** có nằm trong **`last Keys`** và không phải là phím hiện tại hay không; điều này cũng được gọi là nhả một nút (phím hiện tại được lưu trong **`uVar1`**).

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

Trong đoạn code trước, bạn có thể thấy chúng ta đang so sánh **uVar1** (vị trí chứa **giá trị của nút được nhấn**) với một số giá trị:

- Đầu tiên, nó được so sánh với **giá trị 4** (nút **SELECT**): Trong thử thách này, nút đó sẽ xóa màn hình
- Sau đó, giá trị được so sánh với **8** (nút **START**); trong thử thách này, nhánh đó kiểm tra xem mã đã nhập có hợp lệ hay không.
  - Trong trường hợp này, biến **`DAT_030000d8`** được so sánh với 0xf3 và nếu giá trị trùng khớp thì một đoạn code sẽ được thực thi.
- Trong mọi trường hợp khác, một bộ đếm (`DAT_030000d4`) sẽ được kiểm tra và tăng lên.\
  Khi bộ đếm nhỏ hơn 8, các giá trị của những phím được nhấn sẽ được cộng dồn vào `DAT_030000d8`.

Vì vậy, trong thử thách này, khi biết giá trị của các nút, bạn cần **nhấn một tổ hợp có độ dài nhỏ hơn 8 sao cho tổng các giá trị bằng 0xf3.**

**Tài liệu tham khảo cho hướng dẫn này:** [bài viết hướng dẫn giải thử thách Nostalgia đã lưu trữ](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Khóa học

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (gỡ rối nhị phân)

## References

- [1] [Đơn giản hóa việc làm rối MBA với CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Kho lưu trữ Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Giải mã chuỗi Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - chuỗi Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - hướng dẫn reverse GBA (đã lưu trữ)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Đánh bại reverse engineering có AI hỗ trợ, hoặc ít nhất là thử](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Phương pháp so sánh đồ thị luồng điều khiển dựa trên việc khớp các basic block](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Kho lưu trữ Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Cơ chế làm rối Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Sử dụng độ tương đồng của đồ thị luồng điều khiển để tự động gỡ rối các binary Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Kho lưu trữ Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Cập nhật bộ công cụ Golang của Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [Phân tích mã được quản lý của REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Hướng dẫn về REA CLI và bằng chứng](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Quy trình làm phẳng luồng điều khiển trong Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Xâm nhập zero-day PaperCut MF, Java Loader, Web Shell và AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README của IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Triển khai máy chủ bridge cho IDA](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Triển khai máy chủ bridge cho Ghidra](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) liên kết với địa chỉ wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Bộ công cụ reverse engineering Godot](https://github.com/figurophobia/gore)
- [26] [Triển khai khôi phục khóa của gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Định dạng blob mã hóa của gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Triển khai lệnh và khôi phục của gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
