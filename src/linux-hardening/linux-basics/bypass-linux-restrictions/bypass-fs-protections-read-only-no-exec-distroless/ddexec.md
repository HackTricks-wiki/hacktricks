# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Bối cảnh

Linux thường thực thi chương trình từ các tệp thực thi được lưu trên đĩa hoặc trong bộ nhớ. Hệ thống có thể nhận diện tệp thực thi bằng pathname hoặc file descriptor, vì vậy không phải lúc nào cũng cần pathname thông thường trong filesystem.<sup>[[2]](#references)</sup>

DDexec / EverythingExec sử dụng bộ nhớ của một **process đang chạy**. Trang [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) trình bày việc thực thi từ tệp ẩn danh cùng các phương pháp phát hiện và thu thập dữ liệu pháp chứng liên quan; [tổng quan về Memory Bypasses](index.html#memory-bypasses) cũng liên kết đến MemExec và Memdlopen.<sup>[[1]](#references)</sup>

Kỹ thuật này cho phép bạn **vượt qua các kỹ thuật bảo vệ phổ biến như read-only, noexec, whitelist tên tệp và whitelist hash**.<sup>[[1]](#references)</sup>

## Phụ thuộc

Script cuối cùng cần các công cụ sau để hoạt động; chúng phải có thể truy cập được trên hệ thống bạn đang tấn công (theo mặc định, bạn sẽ tìm thấy tất cả các công cụ này ở mọi nơi):

```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```

## Kỹ thuật

Nếu có thể tùy ý sửa đổi bộ nhớ của một tiến trình, bạn có thể chiếm quyền kiểm soát nó. Việc này có thể được dùng để chiếm quyền điều khiển một tiến trình đang chạy và thay thế nó bằng một chương trình khác. Ta có thể thực hiện việc này bằng syscall `ptrace()` (đòi hỏi bạn có khả năng thực thi syscall hoặc có sẵn gdb trên hệ thống) hoặc, thú vị hơn, bằng cách ghi vào `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Tệp `/proc/$pid/mem` ánh xạ một-một toàn bộ không gian địa chỉ của một tiến trình (_ví dụ_, từ `0x0000000000000000` đến `0x7ffffffffffff000` trên x86-64). Điều này có nghĩa là việc đọc hoặc ghi vào tệp này tại offset `x` tương đương với việc đọc hoặc sửa đổi nội dung tại địa chỉ ảo `x`.

Hiện tại, ta cần giải quyết bốn vấn đề cơ bản:

- Nói chung, chỉ root và chủ sở hữu chương trình mới có thể sửa đổi tệp này.
- ASLR.
- Nếu cố đọc hoặc ghi vào một địa chỉ không được ánh xạ trong không gian địa chỉ của chương trình, ta sẽ gặp lỗi I/O.

Có các giải pháp cho những vấn đề này. Tuy không hoàn hảo, nhưng chúng vẫn hữu ích:

- Hầu hết trình thông dịch shell đều cho phép tạo các file descriptor, sau đó được các tiến trình con kế thừa. Ta có thể tạo một fd trỏ đến tệp `mem` của shell với quyền ghi... nhờ đó, các tiến trình con sử dụng fd này có thể sửa đổi bộ nhớ của shell.
- ASLR thậm chí không phải là vấn đề; ta có thể kiểm tra tệp `maps` của shell hoặc bất kỳ tệp nào khác trong procfs để lấy thông tin về không gian địa chỉ của tiến trình.
- Vì vậy, ta cần dùng `lseek()` để di chuyển vị trí trong tệp. Không thể thực hiện việc này từ shell nếu không dùng `dd` khét tiếng.

### Chi tiết hơn

Các bước tương đối đơn giản và không đòi hỏi chuyên môn để hiểu:<sup>[[1]](#references)</sup>

- Phân tích binary mà ta muốn chạy và loader để xác định các ánh xạ mà chúng cần. Sau đó tạo một "shell"code thực hiện, nói khái quát, các bước tương tự như kernel thực hiện mỗi khi gọi `execve()`:
  - Tạo các ánh xạ đó.
  - Đọc các binary vào những ánh xạ này.
  - Thiết lập quyền.
  - Cuối cùng, khởi tạo stack với các đối số cho chương trình và đặt auxiliary vector (cần thiết cho loader).
  - Nhảy vào loader và để nó xử lý phần còn lại (nạp các thư viện mà chương trình cần).
- Lấy từ tệp `syscall` địa chỉ mà tiến trình sẽ quay lại sau syscall đang thực thi.
- Ghi đè vị trí đó bằng shellcode của ta; vị trí này có quyền thực thi (thông qua `mem`, ta có thể sửa đổi các trang không có quyền ghi).
- Truyền chương trình ta muốn chạy vào stdin của tiến trình (sẽ được "shell"code đó `read()`).
- Lúc này, loader sẽ nạp các thư viện cần thiết cho chương trình và nhảy vào chương trình đó.

**Xem công cụ tại** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Có một số lựa chọn thay thế cho `dd`; một trong số đó là `tail`, hiện là chương trình mặc định dùng để `lseek()` trong tệp `mem` (đây vốn là mục đích duy nhất khi dùng `dd`). Các lựa chọn thay thế đó là:<sup>[[1]](#references)</sup>

```bash
tail
hexdump
cmp
xxd
```

Bằng cách thiết lập biến `SEEKER`, bạn có thể thay đổi seeker được sử dụng, _ví dụ_:

```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Nếu tìm thấy một seeker hợp lệ khác chưa được triển khai trong script, bạn vẫn có thể sử dụng nó bằng cách đặt biến `SEEKER_ARGS`:

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Chặn cái này đi, EDR.

## References

- [1] [DDexec: Kỹ thuật chạy file binary không cần tệp và một cách kín đáo trên Linux](https://github.com/arget13/DDexec)
- [2] [execveat(2) — trang hướng dẫn sử dụng Linux](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
