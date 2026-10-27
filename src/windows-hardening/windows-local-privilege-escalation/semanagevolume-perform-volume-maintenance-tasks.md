# SeManageVolumePrivilege: Lạm dụng bảo trì volume và xác thực quyền truy cập thô

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan

Quyền người dùng Windows: Thực hiện các tác vụ bảo trì volume (hằng số: SeManageVolumePrivilege).

Quyền này cho phép thực hiện các thao tác bảo trì volume như chống phân mảnh và tạo hoặc xóa volume. Microsoft cảnh báo rằng người có quyền này có thể mở rộng tệp vào vùng lưu trữ chứa dữ liệu khác, rồi đọc hoặc sửa đổi các byte đã chiếm được.<sup>[[1]](#references)</sup>

Không nên xem việc có `SeManageVolumePrivilege` là bảo đảm có quyền truy cập đĩa thô. Microsoft nêu rõ rằng việc mở đĩa hoặc volume vật lý qua `CreateFile` để truy cập trực tiếp đòi hỏi đặc quyền quản trị viên, đồng thời các kiểm tra quyền truy cập đối tượng/thiết bị thông thường vẫn được áp dụng. Trên một bản dựng hoặc sản phẩm cụ thể, hãy kiểm tra xem token, ACL thiết bị, quyền truy cập được yêu cầu, cờ chia sẻ và trạng thái volume có cho phép mở handle thô hay không trước khi khẳng định có thể đọc tùy ý tệp.<sup>[[3]](#references)</sup>

Mặc định: Quản trị viên trên máy chủ và bộ điều khiển miền.<sup>[[1]](#references)</sup>

## Các tình huống lạm dụng

- Nếu tài khoản thực sự có thể lấy được handle volume thô cho phép đọc, trình phân tích cú pháp có hỗ trợ NTFS có thể bỏ qua ACL từng tệp và khôi phục các tệp được bảo vệ hoặc bị khóa từ các cluster đã cấp phát.
- Các mục tiêu tiềm năng gồm nội dung bị khóa hoặc được bảo vệ bằng ACL trong `C:\Windows\System32`, registry hive, khóa chính DPAPI, SAM và—khi có thể truy cập riêng qua snapshot hoặc volume ngoại tuyến—`ntds.dit`.
- Trên máy chủ dịch vụ chứng chỉ, các vị trí khóa phần mềm hữu ích gồm `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` và `%ProgramData%\Microsoft\Crypto\Keys`; việc khôi phục tệp chỉ hữu ích khi có thể xuất vật liệu khóa và cũng có thể giải mã tệp đó.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Trên máy chủ AD CS, khôi phục thành công khóa riêng tư CA **có thể xuất/được hỗ trợ bằng phần mềm** có thể cho phép lạm dụng Golden Certificate. Các thiết kế dùng khóa phần cứng hoặc khóa không thể xuất sẽ làm thay đổi hướng khai thác này.<sup>[[2]](#references)</sup>
- Một số công cụ bảo trì volume dùng `FSCTL_SD_GLOBAL_CHANGE` để thay thế các mục ACL của hệ thống tệp khi thao tác đó được cho phép. Cách này thay đổi quyền kiểm soát truy cập thay vì đọc thụ động các khối thô, có thể ảnh hưởng đến phần lớn volume và cần được xác thực với token cũng như hành vi thực tế của thiết bị. [Mã nguồn công cụ](https://github.com/CsEnox/SeManageVolumeExploit) cho thấy cơ chế cụ thể này; chỉ có đặc quyền không chứng minh được rằng cách này sẽ thành công.
- Có quyền truy cập tệp nhờ thay đổi ACL không đồng nghĩa với việc giải mã được tệp mã hóa bằng EFS. Muốn có bản rõ vẫn cần khóa riêng tư khôi phục hoặc khóa riêng tư của người dùng tương ứng. Tương tự, việc xuất khóa CA được hỗ trợ bằng phần mềm bằng [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) phụ thuộc vào việc khóa có sẵn cục bộ, có thể xuất và có thể truy cập hay không.

Lưu ý: Bạn vẫn cần trình phân tích cấu trúc NTFS trừ khi dùng các công cụ hỗ trợ. Nhiều công cụ có sẵn đã trừu tượng hóa việc truy cập thô.

## Kỹ thuật thực tế

- Mở handle volume thô và đọc các cluster:

<details>
<summary>Nhấn để mở rộng</summary>

```powershell
# Validation attempt: current Windows versions normally require an administrative token
$fs = [System.IO.File]::Open("\\.\\C:",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf,0,$buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\\temp\\c_first_mb.bin", $buf)
```

```csharp
// C# (compile with Add-Type) – read an arbitrary offset of \\.\nusing System;
using System.IO;
class R {
  static void Main(string[] a){
    using(var fs = new FileStream("\\\\.\\C:", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)){
      fs.Position = 0x100000; // seek
      var buf = new byte[4096];
      fs.Read(buf,0,buf.Length);
      File.WriteAllBytes("C:\\temp\\blk.bin", buf);
    }
  }
}
```

</details>

- Dùng công cụ hỗ trợ NTFS để khôi phục các tệp cụ thể từ volume thô:
  - RawCopy/RawCopy64 (sao chép ở cấp sector các tệp đang được sử dụng)
  - FTK Imager hoặc The Sleuth Kit (tạo ảnh đĩa chỉ đọc, sau đó carve tệp)
  - vssadmin/diskshadow + bản sao shadow, sau đó sao chép tệp mục tiêu từ snapshot (nếu bạn có thể tạo VSS; thường cần quyền admin nhưng thường có sẵn cho cùng những operator có SeManageVolumePrivilege)

Các đường dẫn nhạy cảm thường cần nhắm đến:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (bí mật cục bộ)
- C:\Windows\NTDS\ntds.dit (domain controller – thông qua bản sao shadow)
- C:\Windows\System32\CertSrv\CertEnroll\ (chứng chỉ/CRL của CA; private key nằm trong kho machine key ở trên)

## Liên hệ với AD CS: Forging a Golden Certificate

Nếu bạn có thể đọc private key của Enterprise CA từ kho machine key, bạn có thể giả mạo chứng chỉ client-auth cho các principal bất kỳ và xác thực qua PKINIT/Schannel. Kỹ thuật này thường được gọi là Golden Certificate.<sup>[[2]](#references)</sup> Xem:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Phần: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Phát hiện và gia cố bảo mật

- Giới hạn nghiêm ngặt việc cấp SeManageVolumePrivilege (Perform volume maintenance tasks), chỉ cấp cho admin đáng tin cậy.
- Giám sát Sensitive Privilege Use và các lần mở process handle tới device object như \\.\C:, \\.\PhysicalDrive0.
- Ưu tiên dùng khóa CA không thể xuất, được HSM hoặc TPM cấu hình đúng cách bảo vệ, để việc sao chép tệp key-container không đủ để khôi phục private-key có thể sử dụng.
- Với application secret nằm ngoài đường dẫn CA-key, DPAPI hoặc DPAPI-NG có thể khiến việc sao chép tệp dữ liệu không đủ để truy cập, bằng cách bảo vệ tệp theo user, machine, group hoặc principal được ủy quyền khác. Cách này không bảo vệ plaintext vốn đã có thể được principal bị xâm phạm truy cập.<sup>[[4]](#references)</sup>
- Đảm bảo các đường dẫn upload, temp và extraction không thể thực thi và được tách biệt (biện pháp phòng thủ trong web context thường đi kèm với chuỗi post-exploitation này).

## References

- [1] [Microsoft – Thực hiện tác vụ bảo trì volume (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege được dùng để đọc CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` với physical disk và volume](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation và DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
