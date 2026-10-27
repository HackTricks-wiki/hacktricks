# Linux Basics

{{#include ../../banners/hacktricks-training.md}}

Đây là điểm khởi đầu để đánh giá host Linux. Các trang này trình bày quy trình privilege escalation tổng quát, các lệnh thực tế, biến môi trường và những hạn chế phổ biến ảnh hưởng đến việc chạy lệnh trên host.

- [Linux privilege escalation](linux-privilege-escalation/README.md) hướng dẫn quá trình enumeration và các hướng local escalation tiềm năng. Nếu cần danh sách tác vụ ngắn gọn hơn, hãy dùng [checklist privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
- [Shell startup, aliases, and history](shell-startup-aliases-and-history.md) giải thích cách phân giải lệnh, thực thi startup file và các dấu vết trong history.
- [Useful Linux commands](useful-linux-commands.md) tổng hợp các lệnh để kiểm tra file, process, service và môi trường.
- [Linux environment variables](linux-environment-variables.md) giải thích cách các giá trị môi trường ảnh hưởng đến việc thực thi và những nơi có thể xuất hiện giá trị nhạy cảm.
- [Bypass Linux restrictions](bypass-linux-restrictions/README.md) trình bày các shell và môi trường thực thi bị giới hạn, bao gồm các biện pháp bảo vệ filesystem, `noexec` và hệ thống distroless.

## Native binary exploitation

Khi quá trình đánh giá phát hiện một executable Linux có lỗ hổng, hãy tham khảo nội dung phù hợp trong Binary Exploitation:

- [ELF format and loader behavior](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) và [binary protections and bypasses](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) giải thích bố cục executable và các biện pháp giảm thiểu.
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) và [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) trình bày các cuộc tấn công luồng điều khiển.
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) và [format strings](../../binary-exploitation/format-strings/README.md) trình bày các hướng khai thác lỗi hỏng bộ nhớ phổ biến khác.

Các case study chuyên về kernel được liên kết từ [Kernel/LPE/CVE material](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
