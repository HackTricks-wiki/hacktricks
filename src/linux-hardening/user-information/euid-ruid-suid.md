# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Các biến định danh người dùng

- **`ruid`**: **Real user ID** xác định người dùng đã khởi chạy tiến trình.<sup>[[1]](#references)</sup>
- **`euid`**: Được gọi là **effective user ID**, đây là định danh người dùng mà hệ thống dùng để xác định đặc quyền của tiến trình. Thông thường, `euid` giống với `ruid`, ngoại trừ các trường hợp như thực thi binary SetUID (khi quá trình chuyển đổi set-user-ID được áp dụng), lúc đó `euid` mang định danh của chủ sở hữu tệp, qua đó cấp các quyền thực thi cụ thể.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: **Saved user ID** này đóng vai trò quan trọng khi một tiến trình có đặc quyền cao (thường chạy với quyền root) cần tạm thời từ bỏ đặc quyền để thực hiện một số tác vụ, rồi khôi phục trạng thái đặc quyền ban đầu sau đó.<sup>[[1]](#references)</sup>

#### Lưu ý quan trọng

Một tiến trình không có đặc quyền chỉ có thể đổi `euid` thành giá trị hiện tại của `ruid`, `euid` hoặc `suid`.<sup>[[3]](#references)</sup>

### Tìm hiểu các hàm set\*uid

- **`setuid`**: Trái với suy nghĩ ban đầu, `setuid` đặt `euid` của tiến trình gọi hàm. Với tiến trình có đặc quyền, hàm này cũng đặt `ruid` và `suid` thành người dùng được chỉ định; sau khi tất cả ID được đặt thành root, tiến trình không thể dùng `setuid` để khôi phục danh tính trước đó. Xem thêm chi tiết trong [trang man của setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** và **`setresuid`**: `setreuid` thay đổi `ruid` và `euid`, còn `setresuid` thay đổi cả ba ID. Với tiến trình không có đặc quyền, `setresuid` chỉ cho phép đặt mỗi ID đích thành giá trị hiện tại của `ruid`, `euid` hoặc `suid`; `setreuid` chỉ cho phép đặt `euid` thành các giá trị đó và `ruid` thành giá trị hiện tại của `ruid` hoặc `euid`. Tiến trình có `CAP_SETUID` có thể gán các giá trị tùy ý cho những ID mà mỗi lời gọi hỗ trợ. Xem thêm trong [trang man của setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) và [trang man của setreuid](https://man7.org/linux/man-pages/man2/setresuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Các chức năng này được thiết kế không phải như một cơ chế bảo mật mà nhằm hỗ trợ luồng hoạt động dự kiến, chẳng hạn khi chương trình thay đổi effective user ID để mang danh tính của người dùng khác.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Đáng chú ý, lời gọi `setuid` có đặc quyền có thể gán cả ba ID, trong khi `setreuid` và `setresuid` cung cấp các cơ chế kiểm soát khác nhau; phân biệt các hàm này là điều cần thiết để hiểu các chuyển đổi user-ID.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Cơ chế thực thi chương trình trong Linux

#### **Lời gọi hệ thống `execve`**

- **Chức năng**: `execve` khởi chạy chương trình được xác định bởi đối số đầu tiên. Hàm nhận hai đối số dạng mảng: `argv` chứa các đối số và `envp` chứa môi trường.<sup>[[5]](#references)</sup>
- **Hành vi**: Hàm giữ lại không gian bộ nhớ của tiến trình gọi nhưng làm mới stack, heap và các segment dữ liệu. Mã của chương trình được thay thế bằng chương trình mới.<sup>[[5]](#references)</sup>
- **Bảo toàn User ID**:
  - `ruid` và các group ID bổ sung không thay đổi.<sup>[[5]](#references)</sup>
  - `euid` thường không thay đổi, nhưng có thể thay đổi nếu chương trình mới có bit SetUID.<sup>[[5]](#references)</sup>
  - `suid` được cập nhật từ `euid` sau khi thực thi.<sup>[[5]](#references)</sup>
- **Tài liệu**: Xem thông tin chi tiết trong [trang man của `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **Hàm `system`**

- **Chức năng**: Khác với `execve`, `system` hoạt động như thể tạo tiến trình con bằng `fork` rồi thực thi lệnh trong tiến trình con đó bằng `execl`.<sup>[[6]](#references)</sup>
- **Thực thi lệnh**: Thực thi lệnh thông qua `sh` bằng `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Hành vi**: Vì `execl` là một lời gọi thuộc nhóm `exec`, nó hoạt động tương tự `execve` nhưng trong ngữ cảnh của một tiến trình con mới.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Tài liệu**: Xem thêm thông tin trong [trang man của `system`](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Hành vi của `bash` và `sh` với SUID**

- **`bash`**:
  - Có tùy chọn `-p` ảnh hưởng đến cách xử lý `euid` và `ruid`.<sup>[[7]](#references)</sup>
  - Khi không có `-p`, `bash` đặt `euid` thành `ruid` nếu ban đầu chúng khác nhau.<sup>[[7]](#references)</sup>
  - Khi có `-p`, giá trị `euid` ban đầu được giữ nguyên.<sup>[[7]](#references)</sup>
  - Xem thêm chi tiết trong [trang man của `bash`](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
  - POSIX `sh` không định nghĩa tùy chọn bảo toàn đặc quyền `-p` theo kiểu Bash.<sup>[[8]](#references)</sup>
  - Danh sách tùy chọn POSIX có `-i`, dùng để chọn chế độ tương tác và có thể bị từ chối khi real ID và effective ID khác nhau.<sup>[[8]](#references)</sup>
  - Xem thêm thông tin trong [trang man của `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Các cơ chế này có cách hoạt động khác nhau, cung cấp nhiều lựa chọn linh hoạt để thực thi và chuyển đổi giữa các chương trình, đồng thời có những điểm riêng trong cách quản lý và bảo toàn user ID.

### Kiểm tra hành vi User ID khi thực thi

Các ví dụ được lấy từ https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail; hãy xem để biết thêm thông tin.<sup>[[1]](#references)</sup>

#### Trường hợp 1: Dùng `setuid` với `system`

**Mục tiêu**: Tìm hiểu tác động của `setuid` khi kết hợp với `system` và `bash` làm `sh`.

**Mã C**:

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    system("id");
    return 0;
}
```

**Biên dịch và quyền hạn:**

```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

**Phân tích:**

- `ruid` và `euid` ban đầu lần lượt là 99 (nobody) và 1000 (frank).
- Trong ngữ cảnh không có đặc quyền này, `setuid(1000)` giữ `ruid` ở mức 99 và `euid` ở mức 1000.<sup>[[1]](#references)</sup>
- `system` thực thi `/bin/bash -c id` do `sh` được liên kết tượng trưng tới `bash`.
- `bash`, khi không có `-p`, điều chỉnh `euid` để khớp với `ruid`, khiến cả hai đều là 99 (nobody).<sup>[[1]](#references)</sup>

#### Trường hợp 2: Sử dụng setreuid với system

**Mã C**:

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setreuid(1000, 1000);
    system("id");
    return 0;
}
```

**Biên dịch và quyền:**

```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```

**Thực thi và Kết quả:**

```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

**Phân tích:**

- `setreuid` đặt cả ruid và euid thành 1000.
- `system` gọi bash, tiến trình này giữ nguyên các user ID do chúng bằng nhau, nên trên thực tế hoạt động với tư cách frank.<sup>[[1]](#references)</sup>

#### Case 3: Sử dụng setuid với execve

Mục tiêu: Khám phá tương tác giữa setuid và execve.

```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    execve("/usr/bin/id", NULL, NULL);
    return 0;
}
```

**Thực thi và kết quả:**

```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

**Phân tích:**

- `ruid` vẫn là 99, nhưng `euid` được đặt thành 1000, phù hợp với tác động của setuid.<sup>[[1]](#references)</sup>

**Ví dụ mã C 2 (Gọi Bash):**

```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    execve("/bin/bash", NULL, NULL);
    return 0;
}
```

**Thực thi và kết quả:**

```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

**Phân tích:**

- Mặc dù `euid` được `setuid` đặt thành 1000, `bash` đặt lại `euid` thành `ruid` (99) do thiếu `-p`.<sup>[[1]](#references)</sup>

**Ví dụ mã C 3 (Sử dụng bash -p):**

```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char *const paramList[10] = {"/bin/bash", "-p", NULL};
    setuid(1000);
    execve(paramList[0], paramList, NULL);
    return 0;
}
```

**Thực thi và Kết quả:**

```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```

## References

- [1] [Hố thỏ SetUID - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - trang man setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - trang man setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - trang man setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - trang man execve](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - trang man system](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - trang man bash](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - trang man POSIX sh](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
