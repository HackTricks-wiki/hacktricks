# Điều tra pháp chứng Docker

{{#include ../../banners/hacktricks-training.md}}

## Sửa đổi container

Có nghi vấn rằng một container Docker nào đó đã bị xâm nhập:

```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```

Bạn có thể dễ dàng **tìm các thay đổi được thực hiện trên hệ thống tệp của container này kể từ khi nó được tạo** bằng:<sup>[[1]](#references)</sup>

```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```

Trong lệnh trước, **C** nghĩa là **Đã thay đổi** và **A** nghĩa là **Đã thêm**.<sup>[[1]](#references)</sup>\
Nếu phát hiện một tệp đáng chú ý như `/etc/shadow` đã bị chỉnh sửa, bạn có thể tải tệp đó từ container xuống để kiểm tra hoạt động độc hại bằng cách:<sup>[[2]](#references)</sup>

```bash
docker cp wordpress:/etc/shadow shadow
```

Bạn cũng có thể **so sánh với bản gốc** bằng cách chạy một container mới và trích xuất tệp từ đó:<sup>[[2]](#references)[[3]](#references)</sup>

```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```

Nếu phát hiện **một tệp đáng ngờ nào đó đã được thêm vào**, bạn có thể truy cập container và kiểm tra tệp đó:<sup>[[4]](#references)</sup>

```bash
docker exec -it wordpress bash
```

## Các thay đổi của image

Khi có một Docker image đã xuất (có thể ở định dạng `.tar`), bạn có thể dùng [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) để **trích xuất bản tóm tắt các thay đổi**:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```

Sau đó, bạn có thể **giải nén** image và **truy cập các blob** để tìm kiếm những tệp đáng ngờ mà bạn có thể đã phát hiện trong lịch sử thay đổi:<sup>[[7]](#references)</sup>

```bash
tar -xf image.tar
```

### Phân tích cơ bản

Bạn có thể lấy **thông tin cơ bản** từ image đang chạy:<sup>[[8]](#references)</sup>

```bash
docker inspect <image>
```

Bạn cũng có thể lấy bản tóm tắt **lịch sử thay đổi** bằng cách:<sup>[[9]](#references)</sup>

```bash
docker history --no-trunc <image>
```

Bạn cũng có thể tạo **dockerfile từ một image** bằng:<sup>[[10]](#references)</sup>

```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```

### Dive

Để tìm các tệp được thêm/sửa đổi trong docker images, bạn cũng có thể dùng tiện ích [**dive**](https://github.com/wagoodman/dive) (tải xuống từ [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):<sup>[[11]](#references)[[12]](#references)</sup>

Nạp archive đã lưu vào Docker trước khi mở image tag của nó bằng dive:<sup>[[11]](#references)[[13]](#references)</sup>

```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```

Điều này cho phép bạn **duyệt qua các blob khác nhau của docker images** và kiểm tra những tệp nào đã bị sửa đổi/thêm/xóa. Dùng **tab** để chuyển sang chế độ xem khác và **space** để thu gọn/mở rộng thư mục.<sup>[[11]](#references)</sup>

Với dive, bạn sẽ không thể truy cập nội dung của các stage khác nhau trong image. Để làm vậy, bạn cần **giải nén từng layer và truy cập vào chúng**.\
Bạn có thể giải nén tất cả các layer từ một image bằng cách chạy lệnh sau trong thư mục đã giải nén image:

```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```

## Thông tin xác thực trong bộ nhớ

Trên Linux, PID namespace tổ tiên của host có thể nhìn thấy các process trong PID namespace con của container, vì vậy danh sách process trên host như `ps -ef` có thể hiển thị chúng.<sup>[[14]](#references)</sup>

Khi thông tin xác thực, capabilities và chính sách LSM/ptrace của host cho phép, một điều tra viên trên host có đủ quyền có thể **dump bộ nhớ process** và tìm kiếm **thông tin xác thực**, [**giống như trong ví dụ sau**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Docker container diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker container cp](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker container exec](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [Các định nghĩa analyzer của container-diff](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image history](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [README của Dive v0.10.0](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Bản phát hành Dive v0.10.0](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
