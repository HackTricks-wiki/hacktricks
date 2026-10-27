# Containers và Namespaces

{{#include ../../banners/hacktricks-training.md}}

Container là một tiến trình Linux chạy với cấu hình cô lập và đặc quyền. Hãy đánh giá đồng thời runtime, tài nguyên host được mount, các capability được cấp và cài đặt namespace. [Tổng quan về bảo mật container](container-security/README.md) giải thích các lớp này và liên kết đến từng biện pháp kiểm soát.

- [Leo thang đặc quyền qua Containerd (`ctr`)](containerd-ctr-privilege-escalation.md) tập trung vào quyền truy cập vào giao diện quản lý của containerd.
- [Leo thang đặc quyền qua RunC](runc-privilege-escalation.md) trình bày các nội dung leo thang đặc quyền riêng cho runtime.
- [Bảo mật container](container-security/README.md) giải thích về runtime, API bị lộ, rủi ro từ image, mount nhạy cảm, container đặc quyền, hoạt động đánh giá và các biện pháp bảo vệ như namespace, seccomp và kiểm soát truy cập bắt buộc.
{{#include ../../banners/hacktricks-training.md}}
