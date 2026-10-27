# Windows Service Triggers: Liệt kê và khai thác

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers cho phép Service Control Manager (SCM) khởi động/dừng một service khi một điều kiện xảy ra (ví dụ: địa chỉ IP khả dụng, có kết nối đến named pipe, hoặc một sự kiện ETW được phát). Ngay cả khi không có quyền SERVICE_START trên service mục tiêu, bạn vẫn có thể khởi động service bằng cách khiến trigger của nó được kích hoạt.<sup>[[1]](#references)</sup>

Trang này tập trung vào các cách liệt kê thuận tiện cho attacker và những phương pháp đơn giản để kích hoạt các trigger phổ biến.

> Mẹo: Khởi động một service tích hợp có đặc quyền (ví dụ: RemoteRegistry, WebClient/WebDAV, EFS) có thể mở ra các RPC/named-pipe listener mới và mở khóa những chuỗi khai thác tiếp theo.

## Liệt kê Service Triggers

- sc.exe (local)
  - Liệt kê trigger của một service: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
  - Trigger nằm tại: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
  - Dump đệ quy: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
  - Gọi QueryServiceConfig2 với SERVICE_CONFIG_TRIGGER_INFO (8) để lấy SERVICE_TRIGGER_INFO.
    - Tài liệu: QueryServiceConfig2[W/A] và SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC qua MS‑SCMR (remote)
  - Có thể truy vấn SCM từ xa để lấy thông tin trigger bằng MS‑SCMR. Titanis của TrustedSec hỗ trợ tính năng này: `Scm.exe qtriggers`.
  - Impacket định nghĩa các cấu trúc trong msrpc MS-SCMR; bạn có thể triển khai truy vấn từ xa bằng các cấu trúc đó.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (liệt kê hàng loạt)
  - Nhanh chóng liệt kê mọi service có khóa `TriggerInfo`:
    ```powershell
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
      Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
      ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
    ```
- PowerShell (lập trình)
  - Module `NtObjectManager` của James Forshaw cung cấp `Get-Win32ServiceTrigger` để phân tích metadata của trigger mà không cần trích xuất từ đầu ra của `sc.exe`.

## Các loại trigger có giá trị cao và cách kích hoạt chúng

### Trigger endpoint mạng

Các trigger này khởi động một service khi client cố gắng kết nối đến một IPC endpoint. Chúng hữu ích với người dùng có đặc quyền thấp vì SCM sẽ tự động khởi động service trước khi client của bạn thực sự có thể kết nối.<sup>[[1]](#references)</sup>

- Trigger named pipe
  - Hành vi: Một lần thử kết nối của client tới \\.\pipe\<PipeName> khiến SCM khởi động service để service bắt đầu lắng nghe.
  - Kích hoạt (PowerShell):
    ```powershell
    $pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
    try { $pipe.Connect(1000) } catch {}
    $pipe.Dispose()
    ```
  - Ghi chú nội bộ: các trigger named pipe được hỗ trợ bởi `npsvctrig.sys`, một filesystem minifilter theo dõi các lần mở tên pipe trigger đã đăng ký. Vì vậy, lần thử mở có thể khởi động service ngay cả trước khi service tự tạo/đang lắng nghe trên pipe.<sup>[[5]](#references)</sup>
  - Xem thêm: Named Pipe Client Impersonation để khai thác sau khi khởi động.

- RPC endpoint trigger (Endpoint Mapper)
  - Cách hoạt động: Truy vấn Endpoint Mapper (EPM, TCP/135) về UUID giao diện liên kết với một service sẽ khiến SCM khởi động service đó để nó có thể đăng ký endpoint.
  - Kích hoạt (Impacket):
    ```bash
    # Queries local EPM; replace UUID with the service interface GUID
    python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
    ```

### Trigger tùy chỉnh (ETW)

Một service có thể đăng ký trigger được liên kết với một ETW provider/event. Nếu không cấu hình thêm bộ lọc nào (keyword/level/binary/string), bất kỳ event nào từ provider đó cũng sẽ khởi động service.<sup>[[1]](#references)</sup>

- Ví dụ (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
  - Liệt kê trigger: `sc.exe qtriggerinfo webclient`
  - Xác minh provider đã được đăng ký: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
  - Việc phát các event phù hợp thường cần code ghi log vào provider đó; nếu không có bộ lọc, event nào cũng đủ.
  - Cấu trúc C tối giản để phát event từ provider (khi không cấu hình thêm bộ lọc ETW):
    ```c
    GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
    REGHANDLE h; EVENT_DESCRIPTOR d;
    EventRegister(&g, NULL, NULL, &h);
    EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
    EventWrite(h, &d, 0, NULL);
    EventUnregister(h);
    ```

### Group Policy Triggers

Các loại phụ: Machine/User. Trên các máy chủ đã join domain có policy tương ứng, trigger chạy khi khởi động. Chỉ chạy `gpupdate` sẽ không kích hoạt nếu không có thay đổi, nhưng:<sup>[[1]](#references)</sup>

- Kích hoạt: `gpupdate /force`
  - Nếu tồn tại loại policy liên quan, thao tác này sẽ kích hoạt trigger một cách đáng tin cậy và khởi chạy service.

### IP Address Available

Kích hoạt khi nhận được IP đầu tiên (hoặc mất IP cuối cùng). Thường được kích hoạt khi khởi động.<sup>[[1]](#references)</sup>

- Kích hoạt: Chuyển đổi kết nối để kích hoạt lại, ví dụ:
  ```cmd
  netsh interface set interface name="Ethernet" admin=disabled
  netsh interface set interface name="Ethernet" admin=enabled
  ```

### Giao diện thiết bị được kết nối

Khởi chạy một service khi có giao diện thiết bị phù hợp được kết nối. Nếu không chỉ định mục dữ liệu, mọi thiết bị khớp với GUID subtype của trigger đều sẽ kích hoạt trigger. Được đánh giá khi boot và khi thiết bị được hot-plug.<sup>[[1]](#references)</sup>

- Kích hoạt: Kết nối/cắm một thiết bị (vật lý hoặc ảo) khớp với class/hardware ID được chỉ định bởi subtype của trigger.

### Trạng thái tham gia domain

Dù cách diễn đạt trên MSDN dễ gây nhầm lẫn, trạng thái domain này được đánh giá khi boot:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → khởi chạy service nếu đã tham gia domain
- DOMAIN_LEAVE_GUID → chỉ khởi chạy service nếu CHƯA tham gia domain

### Thay đổi trạng thái hệ thống – WNF (không được tài liệu hóa)

Một số service sử dụng trigger dựa trên WNF không được tài liệu hóa (SERVICE_TRIGGER_TYPE 0x7). Để kích hoạt, cần publish trạng thái WNF liên quan; chi tiết phụ thuộc vào tên trạng thái. Tài liệu tham khảo: Windows Notification Facility internals.

### Trigger tổng hợp của service (không được tài liệu hóa)

Được quan sát trên Windows 11 ở một số service (ví dụ: CDPSvc). Cấu hình tổng hợp được lưu tại:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Giá trị Trigger của service là một GUID; subkey có GUID đó định nghĩa event tổng hợp. Kích hoạt bất kỳ event thành phần nào cũng sẽ khởi chạy service.<sup>[[1]](#references)</sup>

### Event cổng firewall (đặc điểm bất thường và nguy cơ DoS)

Một trigger giới hạn theo cổng/giao thức cụ thể đã được ghi nhận là khởi chạy khi có bất kỳ thay đổi nào đối với firewall rule (vô hiệu hóa/xóa/thêm), chứ không chỉ với cổng được chỉ định. Tệ hơn, cấu hình cổng mà không có giao thức có thể làm hỏng quá trình khởi động BFE qua các lần reboot, kéo theo lỗi ở nhiều service và khiến việc quản lý firewall bị gián đoạn. Hãy hết sức thận trọng.<sup>[[1]](#references)</sup>

## Quy trình thực tế

1) Liệt kê trigger trên các service đáng chú ý (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Nếu có Network Endpoint trigger:
- Named pipe → thử mở kết nối client tới \\.\pipe\<PipeName>
- RPC endpoint → thực hiện tra cứu Endpoint Mapper cho interface UUID

3) Nếu có ETW trigger:
- Kiểm tra provider và filter bằng `sc.exe qtriggerinfo`; nếu không có filter, bất kỳ event nào từ provider đó cũng sẽ khởi chạy service

4) Với trigger Group Policy/IP/Device/Domain:
- Sử dụng các tác động từ môi trường: `gpupdate /force`, bật/tắt NIC, hot-plug thiết bị, v.v.

## Liên quan

- Sau khi khởi chạy một service đặc quyền thông qua trigger Named Pipe, bạn có thể impersonate service đó:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Tóm tắt lệnh nhanh

- Liệt kê trigger (cục bộ): `sc.exe qtriggerinfo <Service>`
- Xem trong Registry: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC từ xa (Titanis): `Scm.exe qtriggers`
- Kiểm tra ETW provider (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Lưu ý / Ghi chú cho operator

- Trước tiên, kiểm tra kiểu khởi động service bằng `sc.exe qc <Service>`. Nếu là `DISABLED`, kích hoạt trigger là chưa đủ; trước hết bạn phải tìm cách thay đổi cấu hình.
- Các service khởi chạy bằng trigger có thể dừng lại khi chuyển sang trạng thái idle. Nếu hành động tiếp theo của bạn phụ thuộc vào listener tồn tại trong thời gian ngắn (RPC/named pipe/WebDAV), hãy kích hoạt trigger và sử dụng ngay.
- `sc.exe qtriggerinfo` không hiểu đầy đủ mọi loại trigger không được tài liệu hóa. Với trigger tổng hợp trên các bản Windows mới hơn, hãy xác nhận GUID nền và các event thành phần trong `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Ghi chú về phát hiện và hardening

- Tạo baseline và audit TriggerInfo trên các service. Đồng thời xem lại HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents để tìm trigger tổng hợp.
- Theo dõi các lượt tra cứu EPM đáng ngờ đối với UUID của service đặc quyền và các lần thử kết nối named pipe xảy ra trước khi service khởi chạy.
- Hạn chế những ai có thể sửa đổi trigger của service; xem các lỗi BFE bất thường sau khi thay đổi trigger là dấu hiệu đáng ngờ.

## References
- [1] [Có nhiều cách để kích hoạt Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [Hàm QueryServiceConfig2 (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Giao thức từ xa Service Control Manager – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (liệt kê trigger SCM)](https://github.com/trustedsec/Titanis)
- [5] [Reverse npsvctrig.sys - Trigger service Named Pipe (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Khởi chạy WebClient Service bằng chương trình (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)
{{#include ../../banners/hacktricks-training.md}}
