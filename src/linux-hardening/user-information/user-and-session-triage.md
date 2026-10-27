# Người dùng, phiên và dấu vết thông tin xác thực

{{#include ../../banners/hacktricks-training.md}}

Bắt đầu với danh tính sở hữu shell hiện tại, sau đó liệt kê những người dùng khác, nhóm, phiên đang hoạt động và kho lưu trữ thông tin xác thực. Trang [ID người dùng thực, hiệu lực và được lưu](euid-ruid-suid.md) giải thích vì sao đặc quyền hiệu lực của một tiến trình có thể khác với tài khoản đăng nhập của nó.

## Liệt kê danh tính và quyền truy cập dựa trên nhóm

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` bao gồm các tài khoản được quản lý bởi dịch vụ thư mục mà thao tác đọc thuần `/etc/passwd` có thể bỏ sót. Kiểm tra các tài khoản UID 0, shell đăng nhập, thư mục home, nhóm bổ sung và những tài khoản có cấu hình cho phép đăng nhập tương tác ngoài dự kiến. Trang [interesting groups](interesting-groups-linux-pe/README.md) trình bày quyền truy cập được ủy quyền như `sudo`, `docker`, `disk` và `shadow`. Kiểm tra ACL hệ thống tệp thực tế và chính sách cục bộ trước khi xem tên nhóm là một quyền đặc biệt.

Nếu [NSS ánh xạ các truy vấn `passwd`, `group` hoặc `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) tới một cơ sở dữ liệu, hãy xem xét provider đang hoạt động và đường dẫn cấu hình của nó trước khi đánh giá các danh tính dựa trên cơ sở dữ liệu. Với các triển khai NSS dùng PostgreSQL, `/etc/nss-pgsql.conf` và `/etc/nss-pgsql-root.conf` chỉ là các gợi ý về đường dẫn, vì thiết lập kết nối có thể chứa thông tin xác thực. Một database role chỉ có ý nghĩa nếu nó có thể thay đổi các bản ghi mà provider NSS đang hoạt động thực sự trả về và một tài khoản có thể xác thực bằng các bản ghi đó. GID chính bằng 0 đồng nghĩa với tư cách thành viên nhóm root, không phải UID 0; ánh xạ vào nhóm sudo cần có [quy tắc nhóm sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) đang có hiệu lực và mọi bước xác thực bắt buộc. Ánh xạ UID 0 là một ranh giới danh tính khác. Không in chuỗi kết nối hoặc thay đổi bản ghi tài khoản trong quá trình liệt kê thụ động.

Ngoài ra, hãy đối chiếu UID dạng số giữa các tên tài khoản cục bộ. Hai tên trong [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) có thể trỏ đến cùng một danh tính tệp Unix, trong khi bản ghi xác thực đăng nhập của chúng có thể khác nhau. Vì vậy, một bí danh mới được thêm với UID khác 0 dùng chung có thể dẫn đến tệp hoặc tiến trình của người dùng khác sau khi xác thực thành công; điều này không cấp quyền root, trừ khi UID đó hoặc một con đường cấp quyền riêng biệt có quyền này. Việc dùng chung UID có thể là chủ ý. Hãy xác minh nguồn tài khoản (`/etc/passwd` hay NSS), lịch sử tạo tài khoản, shell và thư mục home, chính sách xác thực thực tế, cũng như việc các tài khoản có được phép dùng chung danh tính hay không. Chỉ kiểm tra trùng lặp trong tài khoản cục bộ không thể loại trừ bí danh được quản lý bởi dịch vụ thư mục.

## Tìm các phiên đang hoạt động và gần đây

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Một socket `screen` hoặc `tmux` có thể để lộ một shell hiện có nếu quyền của nó cho phép người dùng hiện tại kết nối. Kiểm tra chủ sở hữu và chế độ quyền của socket trước khi thử truy cập; không phải lúc nào cũng có thể kết nối vào phiên của người dùng khác. Dấu thời gian sudo còn hiệu lực hoặc socket SSH agent cũng có thể liên quan, nhưng việc sử dụng lại phụ thuộc vào danh tính người dùng, quyền và chính sách. Để biết cách lạm dụng agent forwarding, xem [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Một [OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) khác với `SSH_AUTH_SOCK`: `ControlMaster` và `ControlPath` cho phép các SSH client sau này dùng chung một kết nối đã xác thực, trong khi `ControlPersist` có thể giữ master hoạt động sau khi phiên đầu tiên kết thúc. Kiểm tra `.ssh/config` của người dùng hiện tại và các đường dẫn socket `.ssh` ở độ sâu nông, bao gồm chủ sở hữu và quyền. Chỉ riêng tên tệp socket không chứng minh được master còn hoạt động, người dùng hiện tại có thể kết nối hay tài khoản từ xa nào được sử dụng.

## Xem xét các hiện vật của người dùng

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Lịch sử Shell, các tệp khởi động, SSH keys, cấu hình ứng dụng, keyring GPG và cache Kerberos có thể tiết lộ thông tin xác thực hoặc các điểm duy trì quyền truy cập có thể ghi. Cần kiểm tra `authorized_keys` hoặc tệp khởi động Shell có thể ghi của tài khoản có đặc quyền cao hơn. [Trang post-exploitation](../post-exploitation/README.md) trình bày về việc di chuyển thư mục GPG homedir và tìm kiếm thông tin xác thực; [Linux Active Directory](linux-active-directory.md) trình bày về việc tái sử dụng cache Kerberos và keytab. [Trang PAM](../software-information/pam-pluggable-authentication-modules.md) giải thích các rủi ro về chính sách xác thực.
{{#include ../../banners/hacktricks-training.md}}
