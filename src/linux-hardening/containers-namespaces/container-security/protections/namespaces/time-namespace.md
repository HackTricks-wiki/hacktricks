# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Tổng quan

Time namespace ảo hóa một số đồng hồ kiểu đơn điệu thay vì đồng hồ thời gian thực của host. Trên thực tế, điều này có nghĩa là các độ lệch riêng tư áp dụng cho **`CLOCK_MONOTONIC`** và **`CLOCK_BOOTTIME`**, cùng các dạng liên quan chặt chẽ là **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** và **`CLOCK_BOOTTIME_ALARM`**. Nó không ảo hóa **`CLOCK_REALTIME`**, vì vậy `date` và logic kiểm tra thời hạn chứng chỉ vẫn quan sát đồng hồ thời gian thực của host, trừ khi có cơ chế khác can thiệp.<sup>[[1]](#references)</sup>

Mục đích chính là cho phép một tiến trình quan sát các độ lệch thời gian đã trôi qua được kiểm soát mà không làm thay đổi góc nhìn thời gian toàn cục của host. Cách này hữu ích cho quy trình checkpoint/restore, kiểm thử xác định và hành vi runtime nâng cao. Đây thường không phải là biện pháp cô lập nổi bật như mount hoặc user namespace, nhưng vẫn góp phần giúp môi trường tiến trình tự chứa hơn.

Từ góc độ offensive, namespace này thường hữu ích hơn cho **reconnaissance, làm lệch timer và tìm hiểu runtime** so với việc trực tiếp thoát khỏi sandbox. Tuy vậy, nó vẫn đáng lưu ý vì ngày càng nhiều container runtime và quy trình checkpoint/restore có thể yêu cầu namespace này một cách rõ ràng.

## Thực hành

Nếu kernel và userspace của host hỗ trợ, bạn có thể kiểm tra namespace bằng:

```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```

Mức độ hỗ trợ khác nhau tùy phiên bản kernel và công cụ, vì vậy trang này chủ yếu giúp hiểu cơ chế thay vì kỳ vọng cơ chế sẽ hiển thị trong mọi môi trường lab. Điều cần lưu ý là `date` vẫn phản ánh đồng hồ thời gian thực của host, còn các giá trị dựa trên monotonic/boottime mới thay đổi khi cấu hình offset khác 0.

### Lưu ý khi tạo

Time namespace hơi khác thường so với mount, PID hoặc network namespace:<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` tạo một time namespace mới cho **các tiến trình con trong tương lai**.
- Task gọi lệnh vẫn ở time namespace hiện tại.
- Vì vậy, khi gỡ lỗi quá trình thiết lập runtime, `/proc/<pid>/ns/time_for_children>` thường đáng chú ý hơn `/proc/<pid>/ns/time`.

Thời điểm được phép ghi cũng đặc biệt. Phải ghi offset vào `/proc/<pid>/timens_offsets` trước khi time namespace mới được điền đầy đủ các task đang chạy; trên thực tế, runtime thực hiện việc này trong khoảng thời gian thiết lập ngắn giữa lúc tạo namespace và lúc khởi chạy payload cuối cùng. Khi đã có task chạy bên trong, các lần ghi sau sẽ thất bại với `EACCES`. Đây là lý do các runtime cấp thấp xử lý việc thiết lập time namespace như một bước bootstrap sớm, thay vì cố gắng chỉnh offset từ bên trong một tiến trình container đã khởi chạy.<sup>[[1]](#references)</sup>

### Offset thời gian

Linux time namespace cung cấp các offset theo từng namespace thông qua `/proc/<pid>/timens_offsets`. Định dạng gồm tên hoặc ID của clock cùng các độ lệch giây/nanosecond so với time namespace ban đầu.<sup>[[1]](#references)</sup>

Trên thực tế, cách làm hướng đến người dùng đáng tin cậy nhất là để `unshare` ghi các offset đó thay bạn:

```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```

Điểm quan trọng không nằm ở cú pháp lệnh chính xác mà ở hành vi: container có thể quan sát một góc nhìn về thời gian hoạt động khác mà không làm thay đổi đồng hồ hệ thống của host.

### Các cờ hỗ trợ của `unshare`

Các phiên bản `util-linux` gần đây cung cấp các cờ tiện ích tự động ghi các độ lệch khi tạo namespace:

```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```

Các flag này chủ yếu cải thiện khả năng sử dụng, nhưng cũng giúp nhận biết tính năng này dễ hơn trong tài liệu, bộ kiểm thử và các wrapper runtime.

## Cách sử dụng trong runtime

Time namespace còn mới và ít được sử dụng rộng rãi hơn mount namespace hoặc PID namespace. OCI Runtime Specification v1.1 bổ sung hỗ trợ rõ ràng cho namespace `time` và trường `linux.timeOffsets`, đồng thời các runtime hiện đại có thể đưa dữ liệu này vào quy trình khởi động kernel. Một đoạn OCI tối thiểu trông như sau:

```json
{
  "linux": {
    "namespaces": [
      { "type": "time" }
    ],
    "timeOffsets": {
      "monotonic": 86400,
      "boottime": 600
    }
  }
}
```

Điều này quan trọng vì nó biến time namespace từ một primitive kernel ít phổ biến thành thứ mà các runtime có thể yêu cầu một cách portable. Điều này cũng giải thích vì sao các thành phần nội bộ của runtime cần một bước đồng bộ hóa rõ ràng: offset phải được ghi vào `/proc/<pid>/timens_offsets` trước khi payload của container hoàn toàn đi vào namespace mới.

Các stack checkpoint/restore như CRIU là một trong những lý do thực tế chính khiến tính năng này tồn tại. Nếu không có time namespace, việc khôi phục một workload đang tạm dừng sẽ khiến đồng hồ monotonic và đồng hồ thời gian khởi động nhảy một khoảng bằng thời gian workload bị treo.<sup>[[2]](#references)</sup>

## Security Impact

Có ít câu chuyện breakout kinh điển tập trung vào time namespace hơn so với các loại namespace khác. Rủi ro ở đây thường không phải là time namespace trực tiếp cho phép escape, mà là người đọc hoàn toàn bỏ qua nó và do đó không nhận ra cách các runtime nâng cao có thể điều chỉnh hành vi của tiến trình.

Trong các môi trường chuyên biệt, góc nhìn đã bị thay đổi về thời gian monotonic hoặc thời gian khởi động có thể ảnh hưởng đến:

- hành vi timeout và retry
- watchdog và logic lease
- hành vi của `timerfd`, `nanosleep` và `clock_nanosleep`
- hoạt động điều tra số checkpoint/restore
- telemetry về thời gian đã trôi qua và heuristic dựa trên uptime

Vì vậy, dù đây hiếm khi là namespace đầu tiên bạn abuse, nó hoàn toàn có thể giải thích các hành vi thời gian "không thể xảy ra" trong quá trình đánh giá.

## Abuse

Thông thường, ở đây không có primitive breakout trực tiếp, nhưng hành vi đồng hồ đã bị thay đổi vẫn có thể hữu ích để hiểu môi trường thực thi, nhận diện các tính năng runtime nâng cao và phát hiện logic dựa trên timer được đo bằng đồng hồ monotonic thay vì thời gian đồng hồ hệ thống:

```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```

Nếu bạn đang so sánh hai process, những khác biệt ở đây có thể giúp giải thích hành vi thời gian bất thường, hiện tượng phát sinh do checkpoint/restore hoặc sai lệch logging đặc thù môi trường.

Các khía cạnh thực tế có liên quan đến attacker:

- gây nhầm lẫn cho logic backoff, sleep hoặc watchdog được triển khai bằng monotonic clock
- giải thích vì sao `/proc/uptime` và hành vi do timer điều khiển không khớp với kỳ vọng về wall clock ở host
- nhận biết các quy trình CRIU/checkpoint-restore và những tính năng runtime nâng cao khác
- phát hiện các môi trường mà việc tham gia time namespace của target bằng `nsenter -T -t <pid> -- ...` có thể tái tạo hành vi timer cục bộ của container để debug hoặc post-exploitation

Tác động:

- gần như luôn chỉ phục vụ reconnaissance hoặc tìm hiểu môi trường
- hữu ích để giải thích các bất thường về logging, uptime hoặc checkpoint/restore
- hữu ích khi phân tích các thao tác sleep, retry và timer dựa trên monotonic time
- thường không phải là cơ chế container escape trực tiếp

Điểm quan trọng cần lưu ý về khả năng lạm dụng là time namespace không ảo hóa `CLOCK_REALTIME`, vì vậy bản thân chúng không cho phép attacker làm giả wall clock của host hoặc trực tiếp phá vỡ việc kiểm tra certificate expiry trên toàn hệ thống. Giá trị của chúng chủ yếu nằm ở việc gây nhầm lẫn cho logic dựa trên monotonic time, tái tạo các lỗi đặc thù môi trường hoặc tìm hiểu hành vi runtime nâng cao.

## Checks

Các bước kiểm tra này chủ yếu nhằm xác nhận runtime có đang sử dụng time namespace riêng hay không, và liệu nó có thực sự đặt các offset khác không.

```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```

Điều gì đáng chú ý ở đây:

- Trong nhiều môi trường, các giá trị này không dẫn đến phát hiện bảo mật ngay lập tức, nhưng chúng cho biết liệu có đang sử dụng một tính năng runtime chuyên biệt hay không.
- Nếu `time_for_children` khác `time`, caller có thể đã chuẩn bị một time namespace chỉ dành cho tiến trình con mà chính nó chưa tham gia.
- Nếu `date` khớp với host nhưng các giá trị dựa trên monotonic/boottime thì không, có thể bạn đang thấy time namespacing chứ không phải thao túng đồng hồ thực.
- Nếu đang so sánh hai tiến trình, những khác biệt này có thể giải thích các hành vi về thời gian hoặc checkpoint/restore khó hiểu.

Với hầu hết các trường hợp container breakout, time namespace không phải là cơ chế kiểm soát đầu tiên bạn cần kiểm tra. Tuy vậy, một phần hoàn chỉnh về bảo mật container vẫn nên đề cập đến nó, vì đây là một phần của mô hình kernel hiện đại và đôi khi có ý nghĩa trong các tình huống runtime nâng cao.

## References

- [1] [Trang hướng dẫn Linux `time_namespaces(7)`](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Độ lệch đồng hồ theo từng container cho CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)
{{#include ../../../../../banners/hacktricks-training.md}}
