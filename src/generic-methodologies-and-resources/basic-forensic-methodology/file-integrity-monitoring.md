# Giám sát tính toàn vẹn tệp

{{#include ../../banners/hacktricks-training.md}}

## Đường cơ sở

Đường cơ sở là ảnh chụp nhanh một số phần nhất định của hệ thống để **so sánh với trạng thái trong tương lai và làm nổi bật các thay đổi**.

Ví dụ: bạn có thể tính toán và lưu hash của từng tệp trong hệ thống tệp để xác định những tệp đã bị sửa đổi.\
Cách này cũng có thể áp dụng cho tài khoản người dùng đã tạo, tiến trình đang chạy, dịch vụ đang chạy và bất kỳ thành phần nào khác không nên thay đổi nhiều, hoặc không nên thay đổi chút nào.

Một **đường cơ sở hữu ích** thường lưu nhiều thông tin hơn chỉ một giá trị digest: quyền truy cập, chủ sở hữu, nhóm, dấu thời gian, inode, đích symlink, ACL và các thuộc tính mở rộng được chọn cũng đáng được theo dõi.<sup>[[4]](#references)</sup> Từ góc độ truy tìm kẻ tấn công, việc này giúp phát hiện **can thiệp chỉ thay đổi quyền**, **thay thế tệp nguyên tử** và **duy trì quyền truy cập thông qua việc sửa đổi tệp service/unit**, ngay cả khi hash nội dung không phải là thứ thay đổi đầu tiên.

### Giám sát tính toàn vẹn tệp

Giám sát tính toàn vẹn tệp (FIM) là một kỹ thuật bảo mật quan trọng, giúp bảo vệ môi trường CNTT và dữ liệu bằng cách theo dõi các thay đổi trong tệp. Kỹ thuật này thường kết hợp:<sup>[[1]](#references)[[3]](#references)</sup>

1. **So sánh với đường cơ sở:** Lưu siêu dữ liệu và checksum mật mã (ưu tiên `SHA-256` trở lên) để so sánh trong tương lai.
2. **Thông báo theo thời gian thực:** Đăng ký nhận sự kiện tệp gốc của hệ điều hành để biết **tệp nào đã thay đổi, khi nào và lý tưởng nhất là tiến trình/người dùng nào đã tác động đến tệp đó**.
3. **Quét định kỳ:** Khôi phục độ tin cậy sau khi khởi động lại, bỏ lỡ sự kiện, agent ngừng hoạt động hoặc có hoạt động chống điều tra số có chủ đích.

Để truy tìm mối đe dọa, FIM thường hữu ích hơn khi tập trung vào **các đường dẫn có giá trị cao**, chẳng hạn như:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Các unit `systemd`, vị trí lưu cron, nội dung SSH, module PAM, web root
- Vị trí duy trì quyền truy cập trên Windows, binary dịch vụ, tệp tác vụ đã lên lịch, thư mục startup
- Các lớp ghi được của container và secret/cấu hình được bind-mount

## Backend thời gian thực và điểm mù

### Linux

Backend thu thập sự kiện rất quan trọng:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: dễ dùng và phổ biến, nhưng có thể cạn giới hạn theo dõi và bỏ sót một số trường hợp đặc biệt.
- **`auditd` / audit framework**: phù hợp hơn khi cần biết **ai đã thay đổi tệp** (UID đăng nhập, ID tiến trình và tên tiến trình).
- **`eBPF` / `kprobes`**: các lựa chọn mới hơn được các giải pháp FIM hiện đại sử dụng để bổ sung thông tin cho sự kiện và giảm bớt một số khó khăn vận hành của các triển khai chỉ dùng `inotify`.

Một số vấn đề thực tế cần lưu ý:<sup>[[1]](#references)[[5]](#references)</sup>

- Nếu một chương trình **thay thế** tệp bằng cách thực hiện `write temp -> rename`, việc theo dõi chính tệp đó có thể không còn hữu ích. **Hãy theo dõi thư mục cha**, không chỉ riêng tệp.
- Các bộ thu thập dựa trên `inotify` có thể bỏ lỡ sự kiện hoặc hoạt động kém với **cây thư mục khổng lồ**, **hoạt động hard link** hoặc sau khi **tệp đang được theo dõi bị xóa**.
- Các tập hợp theo dõi đệ quy rất lớn có thể âm thầm gặp lỗi nếu `fs.inotify.max_user_watches`, `max_user_instances` hoặc `max_queued_events` có giá trị quá thấp.
- Với hoạt động giám sát dựa trên `inotify`, hệ thống tệp mạng là một điểm mù vì các thay đổi từ xa không được báo cáo.

Ví dụ về tạo đường cơ sở + xác minh bằng AIDE:<sup>[[4]](#references)</sup>

```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```

Ví dụ về cấu hình FIM của `osquery` tập trung vào các đường dẫn persistence của kẻ tấn công:<sup>[[1]](#references)</sup>

```json
{
  "schedule": {
    "fim": {
      "query": "SELECT * FROM file_events;",
      "interval": 300,
      "removed": false
    }
  },
  "file_paths": {
    "etc": ["/etc/%%"],
    "systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
    "ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
  }
}
```

Nếu cần **quy kết theo tiến trình** thay vì chỉ theo thay đổi ở cấp đường dẫn, hãy ưu tiên telemetry có hỗ trợ audit như `osquery` `process_file_events` hoặc chế độ `whodata` của Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: telemetry syscall không phải là FIM

Trên Linux hiện đại, theo dõi `openat(2)`, `write(2)` hoặc các điểm vào syscall khác **không tương đương với việc giám sát thao tác hệ thống tệp thực tế**. Proof of concept **Curing** năm 2025 xếp hàng các yêu cầu về tệp và mạng thông qua `io_uring`, khiến các sản phẩm hoặc chính sách chỉ gắn với những điểm vào syscall tương ứng cho từng thao tác bị mất telemetry tiến trình. Trong cùng các thử nghiệm, một thành phần FIM giới hạn theo đường dẫn vẫn phát hiện được các sửa đổi tệp, cho thấy đây là **điểm mù do vị trí hook**, không phải cách vượt qua quyền hạn hay đánh bại mọi backend FIM.<sup>[[10]](#references)</sup>

Khi xác thực một sensor, hãy sửa đổi cùng một canary theo nhiều cách: `write` thông thường, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, thay thế nguyên tử và `io_uring`. Không chỉ kiểm tra xem có phát hiện được sự thay đổi hash cuối cùng hay không, mà còn kiểm tra xem sự kiện có giữ lại thông tin về tiến trình chịu trách nhiệm, container/cgroup, đường dẫn hiển thị trong namespace, inode và cặp thao tác đổi tên hay không. Một sự kiện thời gian thực bị thiếu, sau đó là sai lệch được phát hiện trong lần quét định kỳ, phải được xem là **mất telemetry**, không phải một thay đổi thông thường chưa rõ nguyên nhân.<sup>[[10]](#references)[[11]](#references)</sup>

Đối với hoạt động giám sát dựa trên eBPF, hãy ưu tiên các điểm thực thi phổ biến trong kernel thay vì một danh sách các probe tại điểm vào syscall. Ví dụ, chính sách truy cập tệp của Tetragon sử dụng `security_file_permission` để bao quát I/O thông thường, `sendfile`, `copy_file_range`, AIO và `io_uring`; chính sách này cũng bao quát riêng các ánh xạ bộ nhớ bằng `security_mmap_file` và các thay đổi kích thước bằng `security_path_truncate`. Điều này cũng cho thấy vì sao hiếm khi chỉ một hook có thể bao quát đầy đủ.<sup>[[11]](#references)</sup>

### Windows

Trên Windows, FIM hiệu quả hơn khi kết hợp **change journal** với **telemetry tiến trình/tệp có tín hiệu cao**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** cung cấp nhật ký thay đổi tệp liên tục theo từng volume.
- **Sysmon Event ID 11** hữu ích để phát hiện việc tạo/ghi đè tệp.
- **Sysmon Event ID 2** hỗ trợ phát hiện **timestomping**.
- **Sysmon Event ID 15** hữu ích để phát hiện **alternate data stream (ADS) có tên**, chẳng hạn như `Zone.Identifier` hoặc các luồng payload ẩn.

Ví dụ triage USN nhanh:<sup>[[7]](#references)</sup>

```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```

Để tìm hiểu sâu hơn về các ý tưởng anti-forensic liên quan đến **thao túng timestamp**, **lạm dụng ADS** và **can thiệp USN**, hãy xem [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

FIM trong container thường bỏ sót đường dẫn ghi thực tế. Với Docker `overlay2`, filesystem của container kết hợp các layer `lowerdir` chỉ đọc của image với một **upper layer** có thể ghi (`upperdir`/`diff`), và các thao tác ghi vào file của image sẽ được copy lên upper layer đó.<sup>[[8]](#references)</sup> Do đó:

- Chỉ giám sát các đường dẫn **bên trong** một container tồn tại ngắn hạn có thể bỏ sót thay đổi sau khi container được tạo lại.
- Giám sát **đường dẫn trên host** làm nền cho layer có thể ghi hoặc volume được bind mount liên quan thường hữu ích hơn.
- FIM trên các layer của image khác với FIM trên filesystem của container đang chạy.

## Ghi chú săn tìm hướng đến kẻ tấn công

- Theo dõi **định nghĩa dịch vụ** và **bộ lập lịch tác vụ** cẩn thận như các binary. Kẻ tấn công thường duy trì persistence bằng cách sửa unit file, cron entry hoặc task XML thay vì vá `/bin/sshd`.
- Chỉ dùng content hash là chưa đủ. Nhiều vụ xâm nhập lần đầu biểu hiện qua **sự sai lệch owner/mode/xattr/ACL**.
- Nếu nghi ngờ có một vụ xâm nhập tinh vi, hãy làm cả hai việc: dùng **FIM thời gian thực** để phát hiện hoạt động mới và **so sánh baseline ngoại tuyến** từ phương tiện đáng tin cậy.
- Nếu kẻ tấn công có quyền root hoặc thực thi trong kernel, hãy coi agent FIM và database của nó là không đáng tin cậy. Khi có thể, hãy lưu log và baseline từ xa hoặc trên phương tiện chỉ đọc.<sup>[[4]](#references)</sup>

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Giám sát tính toàn vẹn file bằng osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: Trường hợp sử dụng giám sát tính toàn vẹn file (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Giám sát tính toàn vẹn file của Wazuh (Syscheck và chế độ whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Hướng dẫn sử dụng AIDE phiên bản 0.16.2](https://aide.github.io/doc/)
- [5] [Trang hướng dẫn Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Trình điều khiển lưu trữ OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Cài đặt nâng cao Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [Rootkit io_uring vượt qua các công cụ bảo mật Linux (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Truy cập filename: bao quát các đường dẫn đồng bộ, bất đồng bộ, ánh xạ và cắt ngắn (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
