# Thoát khỏi KIOSK

{{#include ../banners/hacktricks-training.md}}

---

## Kiểm tra thiết bị vật lý

| Thành phần    | Hành động                                                            |
| ------------ | ------------------------------------------------------------------ |
| Nút nguồn | Tắt rồi bật lại thiết bị có thể làm lộ màn hình khởi động    |
| Cáp nguồn  | Kiểm tra xem thiết bị có khởi động lại khi bị ngắt nguồn trong thời gian ngắn không |
| Cổng USB    | Kết nối bàn phím vật lý để dùng thêm phím tắt                      |
| Ethernet     | Quét mạng hoặc nghe lén lưu lượng có thể hỗ trợ khai thác sâu hơn           |

## Kiểm tra các thao tác có thể thực hiện trong ứng dụng GUI

**Hộp thoại phổ biến** gồm các tùy chọn **lưu tệp**, **mở tệp**, chọn phông chữ, màu sắc... Hầu hết các hộp thoại này **cung cấp đầy đủ chức năng của Explorer**. Điều này có nghĩa là bạn có thể truy cập các chức năng của Explorer nếu truy cập được những tùy chọn sau:

- Đóng/Đóng dưới dạng
- Mở/Mở bằng
- In
- Xuất/Nhập
- Tìm kiếm
- Quét

Bạn nên kiểm tra xem có thể:

- Sửa đổi hoặc tạo tệp mới
- Tạo symbolic link
- Truy cập các khu vực bị hạn chế
- Thực thi ứng dụng khác

### Thực thi lệnh

Có thể **dùng tùy chọn `Open with`** để mở/thực thi một dạng shell nào đó\*\*.

#### Windows

Ví dụ: _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ Tìm thêm các binary có thể dùng để thực thi lệnh (và thực hiện các thao tác ngoài dự kiến) tại đây: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Xem thêm tại đây: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Vượt qua giới hạn đường dẫn

- **Biến môi trường**: Có nhiều biến môi trường trỏ đến một đường dẫn
- **Các giao thức khác**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic link**
- **Phím tắt**: CTRL+N (mở phiên mới), CTRL+R (thực thi lệnh), CTRL+SHIFT+ESC (Task Manager), Windows+E (mở Explorer), CTRL-B, CTRL-I (Mục yêu thích), CTRL-H (Lịch sử), CTRL-L, CTRL-O (hộp thoại Tệp/Mở), CTRL-P (hộp thoại In), CTRL-S (Lưu dưới dạng)
  - Menu quản trị ẩn: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URI**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **Đường dẫn UNC**: Đường dẫn dùng để kết nối đến thư mục chia sẻ. Hãy thử kết nối đến C$ trên máy cục bộ ("\\\127.0.0.1\c$\Windows\System32")
  - **Các đường dẫn UNC khác:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Thoát khỏi Desktop bị hạn chế (Citrix/RDS/VDI)

- **Chuyển hướng qua hộp thoại**: Dùng hộp thoại *Open/Save/Print-to-file* như một Explorer thu gọn. Thử `*.*` / `*.exe` trong trường tên tệp, nhấp chuột phải vào thư mục để chọn **Open in new window**, và dùng **Properties → Open file location** để mở rộng điều hướng.<sup>[[1]](#references)</sup>
- **Tạo đường dẫn thực thi từ hộp thoại**: Tạo tệp mới rồi đổi tên thành `.CMD` hoặc `.BAT`, hoặc tạo shortcut trỏ đến `%WINDIR%\System32` (hoặc một binary cụ thể như `%WINDIR%\System32\cmd.exe`).
- **Chuyển hướng khởi chạy shell**: Nếu có thể duyệt đến `cmd.exe`, thử **kéo và thả** bất kỳ tệp nào lên đó để mở prompt. Nếu truy cập được Task Manager (`CTRL+SHIFT+ESC`), dùng **Run new task**.
- **Vượt qua Task Scheduler**: Nếu shell tương tác bị chặn nhưng vẫn được phép lên lịch, hãy tạo tác vụ chạy `cmd.exe` (GUI `taskschd.msc` hoặc `schtasks.exe`).
- **Allowlist yếu**: Nếu việc thực thi được cho phép theo **tên tệp/phần mở rộng**, hãy đổi tên payload thành tên được cho phép. Nếu được cho phép theo **thư mục**, hãy sao chép payload vào thư mục chương trình được phép rồi chạy tại đó.
- **Tìm đường dẫn tạm có quyền ghi**: Bắt đầu với `%TEMP%` và liệt kê các thư mục có thể ghi bằng Sysinternals AccessChk.

```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```

- **Bước tiếp theo**: Nếu lấy được shell, chuyển sang checklist Windows LPE:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Tải các binary của bạn

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Truy cập filesystem từ trình duyệt

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Phím tắt

- Sticky Keys – Nhấn SHIFT 5 lần
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Giữ NUMLOCK trong 5 giây
- Filter Keys – Giữ SHIFT bên phải trong 12 giây
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Hiển thị Desktop
- WINDOWS+E – Khởi chạy Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Màn hình khởi động trên các phiên bản Windows mới hơn
- F1 – Trợ giúp F3 – Search
- F6 – Address Bar
- F11 – Bật/tắt chế độ toàn màn hình trong Internet Explorer
- CTRL+H – Lịch sử Internet Explorer
- CTRL+T – Internet Explorer – Tab mới
- CTRL+N – Internet Explorer – Trang mới
- CTRL+O – Mở tệp
- CTRL+S – Lưu CTRL+N – RDP / Citrix mới

### Vuốt

- Vuốt từ trái sang phải để xem tất cả cửa sổ Windows đang mở, thu nhỏ ứng dụng KIOSK và truy cập trực tiếp toàn bộ OS;
- Vuốt từ phải sang trái để mở Action Center, thu nhỏ ứng dụng KIOSK và truy cập trực tiếp toàn bộ OS;
- Vuốt từ cạnh trên vào trong để hiển thị thanh tiêu đề của ứng dụng đang mở ở chế độ toàn màn hình;
- Vuốt lên từ cạnh dưới để hiển thị taskbar trong ứng dụng toàn màn hình.

### Thủ thuật Internet Explorer

#### 'Image Toolbar'

Đây là thanh công cụ xuất hiện ở phía trên bên trái của hình ảnh khi bạn nhấp vào đó. Bạn có thể lưu, in, gửi mail hoặc mở "My Pictures" trong Explorer. Kiosk cần sử dụng Internet Explorer.

#### Shell Protocol

Nhập các URL sau để mở chế độ xem Explorer:

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Hiển thị phần mở rộng tệp

Xem trang này để biết thêm thông tin: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Thủ thuật trình duyệt

Các phiên bản iKat dự phòng:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Tạo hộp thoại phổ biến bằng JavaScript và truy cập file explorer: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Nguồn: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Cử chỉ và nút

- Vuốt lên bằng bốn (hoặc năm) ngón tay / Nhấn nút Home hai lần: Xem chế độ đa nhiệm và chuyển ứng dụng
- Vuốt theo một hướng bất kỳ bằng bốn hoặc năm ngón tay: Chuyển sang ứng dụng tiếp theo/trước đó
- Chụm màn hình bằng năm ngón tay / Chạm nút Home / Vuốt nhanh lên bằng một ngón tay từ cạnh dưới màn hình: Truy cập Home
- Vuốt chậm lên bằng một ngón tay từ cạnh dưới màn hình khoảng 1-2 inch: Dock sẽ xuất hiện
- Vuốt xuống từ cạnh trên màn hình bằng một ngón tay: Xem thông báo
- Vuốt xuống bằng một ngón tay từ góc trên bên phải màn hình: Mở Control Center của iPad Pro
- Vuốt từ cạnh trái màn hình vào khoảng 1-2 inch bằng một ngón tay: Xem Today view
- Vuốt nhanh bằng một ngón tay từ giữa màn hình sang phải hoặc trái: Chuyển sang ứng dụng tiếp theo/trước đó
- Nhấn và giữ nút On/**Off**/Sleep ở góc trên bên phải của **iPad +** Kéo thanh trượt Slide to **power off** hết sang phải: Tắt nguồn
- Nhấn nút On/**Off**/Sleep ở góc trên bên phải của **iPad và nút Home trong vài giây**: Buộc tắt nguồn
- Nhấn nhanh nút On/**Off**/Sleep ở góc trên bên phải của **iPad và nút Home**: Chụp ảnh màn hình; ảnh sẽ xuất hiện ở góc dưới bên trái màn hình. Nhấn nhanh đồng thời cả hai nút; nếu giữ chúng trong vài giây, thiết bị sẽ bị buộc tắt nguồn.<sup>[[3]](#references)</sup>

### Phím tắt

Bạn cần có bàn phím iPad hoặc bộ chuyển đổi bàn phím USB. Ở đây chỉ liệt kê các phím tắt có thể giúp thoát khỏi ứng dụng.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

| Phím | Tên          |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Mũi tên trái |
| →   | Mũi tên phải |
| ↑   | Mũi tên lên   |
| ↓   | Mũi tên xuống |

#### Phím tắt hệ thống

Các phím tắt này dùng cho cài đặt hiển thị và âm thanh, tùy theo cách sử dụng iPad.

| Phím tắt | Thao tác                                                                       |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Giảm độ sáng màn hình                                                          |
| F2       | Tăng độ sáng màn hình                                                          |
| F7       | Lùi về bài hát trước                                                           |
| F8       | Phát/tạm dừng                                                                   |
| F9       | Bỏ qua bài hát                                                                 |
| F10      | Tắt tiếng                                                                       |
| F11      | Giảm âm lượng                                                                   |
| F12      | Tăng âm lượng                                                                   |
| ⌘ Space  | Hiển thị danh sách ngôn ngữ khả dụng; để chọn một ngôn ngữ, nhấn lại phím cách. |

#### Điều hướng iPad

| Phím tắt                                           | Thao tác                                                 |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Về Home                                                 |
| ⌘⇧H (Command-Shift-H)                              | Về Home                                                 |
| ⌘ (Space)                                          | Mở Spotlight                                           |
| ⌘⇥ (Command-Tab)                                   | Liệt kê mười ứng dụng được dùng gần đây nhất             |
| ⌘\~                                                | Chuyển về ứng dụng trước đó                              |
| ⌘⇧3 (Command-Shift-3)                              | Chụp ảnh màn hình (hiện ở góc dưới bên trái để lưu hoặc thao tác) |
| ⌘⇧4                                                | Chụp ảnh màn hình và mở trong trình chỉnh sửa            |
| Nhấn và giữ ⌘                                      | Liệt kê các phím tắt khả dụng cho ứng dụng               |
| ⌘⌥D (Command-Option/Alt-D)                         | Hiển thị dock                                            |
| ^⌥H (Control-Option-H)                             | Nút Home                                                |
| ^⌥H H (Control-Option-H-H)                         | Hiển thị thanh đa nhiệm                                  |
| ^⌥I (Control-Option-i)                             | Bộ chọn mục                                              |
| Escape                                             | Nút quay lại                                             |
| → (Mũi tên phải)                                   | Mục tiếp theo                                            |
| ← (Mũi tên trái)                                   | Mục trước đó                                             |
| ↑↓ (Mũi tên lên, Mũi tên xuống)                    | Chạm đồng thời vào mục đã chọn                           |
| ⌥ ↓ (Option-Mũi tên xuống)                         | Cuộn xuống                                               |
| ⌥↑ (Option-Mũi tên lên)                            | Cuộn lên                                                 |
| ⌥← hoặc ⌥→ (Option-Mũi tên trái hoặc Option-Mũi tên phải) | Cuộn sang trái hoặc phải                           |
| ^⌥S (Control-Option-S)                             | Bật hoặc tắt giọng nói VoiceOver                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Chuyển sang ứng dụng trước đó                            |
| ⌘⇥ (Command-Tab)                                   | Chuyển về ứng dụng ban đầu                               |
| ←+→, sau đó Option + ← hoặc Option+→               | Điều hướng trong Dock                                    |

#### Phím tắt Safari

| Phím tắt                | Thao tác                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Mở vị trí                                         |
| ⌘T                      | Mở tab mới                                       |
| ⌘W                      | Đóng tab hiện tại                                 |
| ⌘R                      | Làm mới tab hiện tại                              |
| ⌘.                      | Dừng tải tab hiện tại                             |
| ^⇥                      | Chuyển sang tab tiếp theo                         |
| ^⇧⇥ (Control-Shift-Tab) | Chuyển về tab trước đó                            |
| ⌘L                      | Chọn trường nhập văn bản/URL để chỉnh sửa         |
| ⌘⇧T (Command-Shift-T)   | Mở tab vừa đóng gần nhất (có thể dùng nhiều lần)  |
| ⌘\[                     | Quay lại một trang trong lịch sử duyệt web         |
| ⌘]                      | Tiến lên một trang trong lịch sử duyệt web         |
| ⌘⇧R                     | Bật Reader Mode                                   |

#### Phím tắt Mail

| Phím tắt                   | Thao tác                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Mở vị trí                     |
| ⌘T                         | Mở tab mới                    |
| ⌘W                         | Đóng tab hiện tại              |
| ⌘R                         | Làm mới tab hiện tại           |
| ⌘.                         | Dừng tải tab hiện tại          |
| ⌘⌥F (Command-Option/Alt-F) | Tìm kiếm trong hộp thư         |

## References

- [1] [Thoát khỏi Citrix và các môi trường desktop bị giới hạn khác](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Đưa tôi một trình duyệt, tôi sẽ đưa bạn một shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 cử chỉ chỉ có trên iPad mà bạn cần biết](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [Hướng dẫn phím tắt iPad](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Các phím tắt bàn phím iPad tốt nhất](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [Phím tắt bàn phím iPad](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Hiển thị phần mở rộng tệp trong Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)
{{#include ../banners/hacktricks-training.md}}
