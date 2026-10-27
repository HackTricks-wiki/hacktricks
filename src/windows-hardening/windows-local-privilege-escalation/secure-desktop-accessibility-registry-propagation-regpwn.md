# LPE thông qua lan truyền Registry của Secure Desktop Accessibility (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan

Các tính năng Accessibility của Windows lưu cấu hình người dùng trong HKCU và lan truyền cấu hình đó đến các vị trí HKLM theo từng phiên. Trong quá trình chuyển sang **Secure Desktop** (màn hình khóa hoặc lời nhắc UAC), các thành phần **SYSTEM** sao chép lại những giá trị này. Nếu **khóa HKLM theo phiên có thể được người dùng ghi**, nó trở thành một điểm nghẽn ghi có đặc quyền, có thể được chuyển hướng bằng **symbolic link của registry**, tạo ra khả năng **ghi registry SYSTEM tùy ý**.<sup>[[1]](#references)</sup>

Kỹ thuật RegPwn lợi dụng chuỗi lan truyền đó bằng một khoảng đua ngắn, được ổn định thông qua **opportunistic lock (oplock)** trên một tệp mà `osk.exe` sử dụng.<sup>[[1]](#references)</sup>

## Chuỗi lan truyền Registry (Accessibility -> Secure Desktop)

Ví dụ về tính năng: **On-Screen Keyboard** (`osk`). Các vị trí liên quan là:

- **Danh sách tính năng toàn hệ thống**:
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Cấu hình theo người dùng (người dùng có quyền ghi)**:
  - `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Cấu hình HKLM theo phiên (do `winlogon.exe` tạo, người dùng có quyền ghi)**:
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (ngữ cảnh SYSTEM)**:
  - `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Quá trình lan truyền khi chuyển sang secure desktop (đơn giản hóa):

1. **`atbroker.exe` của người dùng** sao chép `HKCU\...\ATConfig\osk` sang `HKLM\...\Session<session id>\ATConfig\osk`.
2. **`atbroker.exe` của SYSTEM** sao chép `HKLM\...\Session<session id>\ATConfig\osk` sang `HKU\.DEFAULT\...\ATConfig\osk`.
3. **`osk.exe` của SYSTEM** sao chép `HKU\.DEFAULT\...\ATConfig\osk` trở lại `HKLM\...\Session<session id>\ATConfig\osk`.

Nếu người dùng có quyền ghi vào cây con HKLM theo phiên, bước 2/3 cung cấp khả năng ghi bằng SYSTEM thông qua một vị trí mà người dùng có thể thay thế.<sup>[[1]](#references)</sup>

## Primitive: Ghi Registry SYSTEM tùy ý thông qua Registry Link

Thay khóa theo phiên mà người dùng có quyền ghi bằng một **symbolic link của registry** trỏ đến đích do kẻ tấn công chọn. Khi thao tác sao chép bằng SYSTEM diễn ra, nó đi theo link và ghi các giá trị do kẻ tấn công kiểm soát vào khóa đích bất kỳ.

Ý tưởng chính:

- Đích ghi của tiến trình bị khai thác (người dùng có quyền ghi):
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Kẻ tấn công thay khóa đó bằng một **registry link** trỏ đến bất kỳ khóa nào khác.
- SYSTEM thực hiện thao tác sao chép và ghi vào khóa do kẻ tấn công chọn với quyền SYSTEM.

Điều này tạo ra primitive **ghi registry SYSTEM tùy ý**.<sup>[[1]](#references)</sup>

## Thắng khoảng đua bằng Oplock

Có một khoảng thời gian ngắn giữa lúc **`osk.exe` của SYSTEM** khởi chạy và ghi vào khóa theo phiên. Để khai thác ổn định, exploit đặt một **oplock** trên:

```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```

Khi oplock được kích hoạt, attacker thay key HKLM theo phiên bằng một registry link, chờ thao tác ghi của SYSTEM hoàn tất rồi gỡ link.<sup>[[1]](#references)</sup>

## Luồng khai thác mẫu (Tổng quan)

1. Lấy **session ID** hiện tại từ access token.
2. Khởi chạy một instance `osk.exe` ẩn rồi chờ một lúc (để đảm bảo oplock sẽ được kích hoạt).
3. Ghi các giá trị do attacker kiểm soát vào:
   - `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Đặt **oplock** trên `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Kích hoạt **Secure Desktop** (`LockWorkstation()`), khiến `atbroker.exe` / `osk.exe` chạy với quyền SYSTEM.
6. Khi oplock được kích hoạt, thay `HKLM\...\Session<session id>\ATConfig\osk` bằng một **registry link** trỏ đến target bất kỳ.
7. Chờ một lúc để quá trình sao chép của SYSTEM hoàn tất, rồi gỡ link.<sup>[[1]](#references)</sup>

## Chuyển Primitive thành thực thi SYSTEM

Một chuỗi khai thác đơn giản là ghi đè giá trị **cấu hình service** (ví dụ: `ImagePath`), rồi khởi động service đó. RegPwn PoC ghi đè `ImagePath` của **`msiserver`** và kích hoạt service bằng cách khởi tạo **MSI COM object**, dẫn đến thực thi code với quyền **SYSTEM**.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Liên quan

Để tìm hiểu các hành vi Secure Desktop / UIAccess khác, xem:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [Tạm biệt RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [PoC RegPwn](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
