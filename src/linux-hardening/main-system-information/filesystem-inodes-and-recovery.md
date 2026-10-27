# Hệ thống tệp, Inode và Khôi phục

{{#include ../../banners/hacktricks-training.md}}

Việc lạm dụng hệ thống tệp thường liên quan đến việc gây nhầm lẫn giữa đường dẫn hiển thị và đối tượng nằm phía sau nó.

Ảnh đĩa có thể ẩn một hệ thống tệp khác.<sup>[[1]](#references)</sup> Các mount có quyền ghi có thể bị các tiến trình đặc quyền sử dụng.

Hardlink có thể hiển thị cùng một inode dưới một tên khác.<sup>[[3]](#references)</sup> Các tệp đã xóa vẫn có thể đọc được thông qua file descriptor đang mở.<sup>[[5]](#references)[[6]](#references)</sup>

Trang này tập trung vào kỹ thuật, không hướng đến một lab hay mục tiêu cụ thể nào.

## Ảnh đĩa và Loop Mounts

Một tệp thông thường có thể chứa cả một hệ thống tệp, vì vậy khi được mount, ảnh đĩa có thể hiển thị một cây hệ thống tệp thứ hai.<sup>[[1]](#references)</sup>

Do đó, ảnh sao lưu, thiết bị khối được sao chép, dữ liệu VM hoặc các blob được đổi tên có thể chứa thông tin xác thực, script, SSH key, tệp cấu hình hoặc flag ngay cả khi nhìn từ bên ngoài chúng có vẻ không hữu ích.

Dùng `file` để phân loại các ảnh có khả năng là ảnh đĩa, `blkid` để dò metadata hệ thống tệp đã nhận diện và `strings -a` để quét toàn bộ tệp tìm các chuỗi ký tự có thể in được.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```

Khi được phép mount, hãy dùng loop mount với `ro` để gắn image ở chế độ chỉ đọc; lệnh `find` bên dưới giới hạn độ sâu kiểm tra và loại tệp.<sup>[[1]](#references)[[4]](#references)</sup>

```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```

Nếu không thể mount và image là ext2/ext3/ext4, hãy kiểm tra trực tiếp metadata của nó bằng `debugfs`.<sup>[[2]](#references)</sup>

```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```

Kỹ thuật này hữu ích vì biến một tệp trông bình thường thành một cây filesystem thứ hai.<sup>[[1]](#references)</sup> Hãy xem đây là cách khôi phục dữ liệu ẩn, không phải một hình thức leo thang đặc quyền tự thân.

## Lạm dụng mount có thể ghi

Một mount có thể ghi trở nên nguy hiểm khi một ngữ cảnh có đặc quyền cao hơn về sau tin cậy thứ gì đó bên trong nó. Câu hỏi quan trọng không chỉ là “tôi có thể ghi vào đây không?”, mà còn là “sau này ai sẽ đọc, thực thi, import hoặc tải nội dung từ đây?”.

Dùng `findmnt` để kiểm tra các filesystem đã được mount và các tùy chọn của chúng.<sup>[[9]](#references)</sup>

Tìm các mount có thể ghi và những tiến trình đáng ngờ sử dụng chúng bằng các điều kiện về quyền, loại và ranh giới filesystem được tài liệu hóa của `find`, sau đó dùng `grep` đệ quy để tìm trong các cấu hình có khả năng được những tiến trình đó sử dụng.<sup>[[4]](#references)[[20]](#references)</sup>

```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```

Các kiểu lạm dụng phổ biến:

- Một cron job hoặc dịch vụ systemd chạy script có thể ghi được từ mount.<sup>[[13]](#references)[[14]](#references)</sup>
- Một dịch vụ có đặc quyền tải plugin, cấu hình, template hoặc binary trợ giúp từ mount.
- Một mount chứa các tệp SUID và cho phép sửa đổi, thay thế hoặc thao túng đường dẫn.
- Một container hoặc chroot để lộ đường dẫn dựa trên host mà môi trường bị hạn chế có thể ghi vào. Mount namespace cung cấp các hệ phân cấp mount riêng biệt, trong khi `chroot()` chỉ thay đổi cách phân giải tên đường dẫn và không phải là sandbox hoàn chỉnh.<sup>[[15]](#references)[[16]](#references)</sup>

Mẫu xác thực tổng quát sử dụng cùng các điều kiện `find`.<sup>[[4]](#references)</sup>

```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```

Khi chứng minh tác động trong một phòng lab được ủy quyền, hãy giữ payload dễ quan sát và tối giản, chẳng hạn ghi kết quả của `id` vào một tệp tạm thời.<sup>[[23]](#references)</sup> Kỹ thuật cốt lõi là thực thi trì hoãn thông qua một vị trí có thể ghi đáng tin cậy.

## Inodes và nhầm lẫn đường dẫn

Inode là đối tượng của hệ thống tệp; đường dẫn chỉ là tên trỏ đến đối tượng đó. Siêu dữ liệu về thiết bị và inode giúp bạn phân biệt các đối tượng giữa các hệ thống tệp, còn số lượng liên kết cho thấy có nhiều hard link hay không.<sup>[[3]](#references)</sup> Tên đường dẫn đã bị xóa không phải lúc nào cũng đồng nghĩa dữ liệu đã mất nếu một tiến trình vẫn đang mở tệp đó.<sup>[[5]](#references)</sup>

Các biểu thức điều kiện `find` dưới đây so sánh danh tính inode, số lượng liên kết, ranh giới thiết bị và dấu thời gian.<sup>[[4]](#references)</sup>

So sánh các tệp theo inode và thiết bị bằng `ls -i` cùng các định dạng siêu dữ liệu của `stat`.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```

Tìm mọi đường dẫn hiển thị trỏ đến cùng một inode bằng `find -samefile`.<sup>[[4]](#references)</sup>

```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```

Tìm kiếm trực tiếp theo số inode bằng `find -inum` khi bạn chỉ có siêu dữ liệu.<sup>[[4]](#references)</sup>

```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```

Kỹ thuật này hữu ích khi một tệp xuất hiện dưới tên không như mong đợi, khi ứng dụng xác thực một đường dẫn nhưng lại sử dụng đường dẫn khác, hoặc khi một wrapper có quyền cao tương tác với inode cũng có thể được truy cập ở một nơi khác.

## Hardlink Abuse

Hardlink tạo nhiều tên cho cùng một inode. Chúng không trỏ đến đường dẫn đích như symlink; chúng là các tên tương đương cho cùng một đối tượng tệp.<sup>[[3]](#references)</sup>

Tìm các tệp SUID có nhiều hardlink bằng cách sử dụng các điều kiện về quyền và số lượng liên kết của `find`.<sup>[[4]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Kiểm tra một tệp đáng ngờ bằng `stat` và `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>

```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```

Vì sao điều này quan trọng:

- Một tệp nhạy cảm có thể truy cập được qua một đường dẫn ít hiển nhiên hơn.
- Một trình bao bọc SUID có thể bị ẩn sau tên không có vẻ mang đặc quyền.
- Việc dọn dẹp xóa một tên đường dẫn có thể vẫn để lại một liên kết cứng khác.

sysctl `fs.protected_hardlinks` của Linux có thể hạn chế việc tạo liên kết cứng vượt qua ranh giới đặc quyền.<sup>[[7]](#references)</sup> Các liên kết cứng hiện có vẫn cần được rà soát.

## Khôi phục tệp đã xóa thông qua FD đang mở

Khi một tiến trình vẫn mở một tệp, việc xóa tên đường dẫn cuối cùng của tệp sẽ khiến tệp tồn tại cho đến khi descriptor cuối cùng được đóng; Linux hiển thị các descriptor đó trong `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Tìm các tệp đã xóa nhưng vẫn đang mở bằng cách liệt kê các descriptor trong `/proc` và lọc kết quả hiển thị tệp đang mở.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```

Việc khôi phục thông qua các liên kết này phụ thuộc vào quyền truy cập, vì truy cập theo tham chiếu `/proc/<pid>/fd` chịu sự kiểm tra quyền truy cập ptrace và quyền trên tệp.<sup>[[6]](#references)</sup>

Khi được phép, `readlink` hiển thị đích của descriptor và `cp` sao chép nội dung của nó.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```

Đây là kỹ thuật thực tiễn để khôi phục log đã xóa, bí mật tạm thời, binary bị loại bỏ, tệp đã xoay vòng hoặc script bị xóa sau khi thực thi.

## Khôi phục ext bằng debugfs

Trên các filesystem ext2/ext3/ext4, `debugfs` có thể kiểm tra metadata inode và trích xuất nội dung inode từ thiết bị khối hoặc image; nếu không có `-w`, công cụ sẽ mở filesystem ở chế độ chỉ đọc.<sup>[[2]](#references)</sup> Hãy làm việc trên bản sao hoặc image chỉ đọc bất cứ khi nào có thể.

Liệt kê các mục và kiểm tra inode bằng những yêu cầu của `debugfs` để liệt kê thư mục, xem trạng thái inode và kiểm tra ánh xạ từ inode sang đường dẫn.<sup>[[2]](#references)</sup>

```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```

Dump một inode đã biết bằng lệnh `debugfs dump`, sau đó xác định loại dữ liệu đầu ra được khôi phục bằng `file`.<sup>[[2]](#references)[[10]](#references)</sup>

```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```

Đây không phải là cách khôi phục được đảm bảo. Kết quả phụ thuộc vào trạng thái của hệ thống tệp, việc các block có bị sử dụng lại hay không và metadata còn tồn tại hay không. Với ext3/ext4, hướng dẫn sử dụng `debugfs` lưu ý rằng việc khôi phục inode đã xóa có thể thất bại vì các block dữ liệu inode đã được giải phóng không còn khả dụng.<sup>[[2]](#references)</sup> Kỹ thuật này vẫn hữu ích vì cho phép bạn kiểm tra trạng thái ở cấp inode mà không cần dựa vào việc duyệt đường dẫn thông thường.

## Cạn kiệt Inode và Thứ tự

Cạn kiệt inode xảy ra khi hệ thống tệp hết nút tệp dù dung lượng đĩa trống vẫn còn.<sup>[[8]](#references)[[17]](#references)</sup> Tình trạng này thường gây ra lỗi về độ tin cậy, nhưng cũng có thể lý giải hành vi bất thường khi ứng phó sự cố hoặc phân tích nhanh trong phòng lab.

Dùng `df -i` để báo cáo thông tin inode thay vì mức sử dụng block.<sup>[[8]](#references)</sup>

Kiểm tra áp lực inode bằng `df` và lệnh `find` để đếm các thư mục cha.<sup>[[4]](#references)[[8]](#references)</sup>

```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```

Số inode và dấu thời gian cũng có thể giúp tái dựng hoạt động trong các môi trường lab đơn giản.

Các chỉ thị định dạng của `find` bên dưới hiển thị những trường đó.<sup>[[4]](#references)</sup>

```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```

Hãy xem thứ tự là manh mối, không phải bằng chứng. Các thao tác sao chép, giải nén archive, loại filesystem, khôi phục và ghi đồng thời đều có thể làm thay đổi quy luật cấp phát.

## Ghi chú phòng thủ

- Gắn các image không rõ nguồn gốc ở chế độ chỉ đọc trong quá trình phân tích.<sup>[[1]](#references)</sup>
- Đặt script có đặc quyền, service unit, plugin và đường dẫn helper bên ngoài các mount có thể ghi bởi người dùng.
- Sử dụng `nosuid`, `nodev` và `noexec` khi phù hợp về mặt vận hành; các tùy chọn này vô hiệu hóa việc thực thi set-ID/capability, diễn giải thiết bị hoặc thực thi trực tiếp binary trên mount.<sup>[[1]](#references)</sup> Đừng xem chúng là ranh giới bảo vệ toàn diện.
- Hạn chế quyền truy cập vào `/proc/<pid>/fd`; việc tham chiếu các liên kết này chịu sự kiểm soát của các bước kiểm tra quyền truy cập ptrace và quyền đối với tệp.<sup>[[6]](#references)</sup> Khi có thể, hãy hạn chế metadata tiến trình nói chung và việc kiểm tra chéo giữa các người dùng.
- Giám sát các điểm mount có thể ghi, hardlink bất thường trỏ đến tệp có đặc quyền và các tệp nhạy cảm đã bị xóa nhưng vẫn đang mở.

## References

- [1] [mount(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Tài liệu về /proc/sys/fs/ — Tài liệu Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
