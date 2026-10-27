# Processes, Crontab, Systemd và D-Bus

{{#include ../../banners/hacktricks-training.md}}

Các tác vụ được lên lịch và cơ chế giao tiếp giữa các tiến trình có thể chạy mã với quyền khác với quyền của bên gọi. Trước khi kiểm thử một dịch vụ hoặc tác vụ, hãy kiểm tra chủ sở hữu, lệnh và các đầu vào có thể ghi.

- [Liệt kê tiến trình và đường dẫn dịch vụ](process-enumeration-and-service-paths.md) đề cập đến cây tiến trình, tệp thời gian chạy và chuỗi thực thi systemd.
- [Cron jobs và systemd timers](cron-and-systemd-timers.md) đề cập đến việc tìm kiếm tác vụ được lên lịch và các đầu vào có thể ghi.
- [Liệt kê D-Bus và leo thang đặc quyền bằng command injection](d-bus-enumeration-and-command-injection-privilege-escalation.md) đề cập đến message bus và các phương thức dịch vụ có đặc quyền.
- [Payloads cần thực thi](payloads-to-execute.md) tập hợp các payload có thể dùng khi đã xác định được đường dẫn thực thi.

Để rà soát toàn diện hơn các cron jobs và dịch vụ systemd, hãy dùng [checklist leo thang đặc quyền trên Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
