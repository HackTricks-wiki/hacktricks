# Bảo mật Container

{{#include ../../../banners/hacktricks-training.md}}

## Container Thực Chất Là Gì

Một cách thực tế để định nghĩa container là: container là một **cây tiến trình Linux thông thường** được khởi chạy theo một cấu hình kiểu OCI cụ thể, để nó nhìn thấy một hệ thống tệp được kiểm soát, một tập tài nguyên kernel được kiểm soát và một mô hình đặc quyền bị hạn chế. Tiến trình có thể nghĩ rằng nó là PID 1, có thể nghĩ rằng nó có network stack riêng, có thể nghĩ rằng nó sở hữu hostname và tài nguyên IPC riêng, thậm chí có thể chạy với quyền root bên trong user namespace riêng. Nhưng bên dưới, nó vẫn là một tiến trình trên host được kernel lập lịch như mọi tiến trình khác.

Đây là lý do bảo mật container thực chất là nghiên cứu cách tạo ra ảo giác đó và cách nó thất bại. Nếu mount namespace yếu, tiến trình có thể nhìn thấy hệ thống tệp của host. Nếu user namespace không tồn tại hoặc bị vô hiệu hóa, root bên trong container có thể được ánh xạ quá sát với root trên host. Nếu seccomp không bị giới hạn và tập capability quá rộng, tiến trình có thể gọi các syscall và truy cập những tính năng kernel đặc quyền vốn không nên nằm trong tầm với. Nếu runtime socket được mount bên trong container, container có thể không cần kernel breakout vì chỉ cần yêu cầu runtime khởi chạy một container ngang hàng có nhiều quyền hơn hoặc mount trực tiếp hệ thống tệp gốc của host.

## Container Khác Máy Ảo Như Thế Nào

Thông thường, VM có kernel và ranh giới trừu tượng hóa phần cứng riêng. Điều đó có nghĩa là guest kernel có thể gặp sự cố, panic hoặc bị khai thác mà không đồng nghĩa với việc kernel của host bị kiểm soát trực tiếp. Container không có kernel riêng cho workload. Thay vào đó, nó nhận được một chế độ xem của cùng kernel mà host sử dụng, được lọc và phân tách bằng namespace một cách cẩn thận. Vì vậy, container thường nhẹ hơn, khởi động nhanh hơn, dễ đóng gói dày đặc trên một máy hơn và phù hợp hơn với việc triển khai ứng dụng ngắn hạn. Đổi lại, ranh giới cô lập phụ thuộc trực tiếp hơn nhiều vào việc cấu hình host và runtime có chính xác hay không.

Điều này không có nghĩa container là "không an toàn" còn VM thì "an toàn". Mô hình bảo mật của chúng khác nhau. Một stack container được cấu hình tốt với thực thi rootless, user namespace, seccomp mặc định, tập capability nghiêm ngặt, không chia sẻ namespace của host và cơ chế thực thi SELinux hoặc AppArmor mạnh có thể rất vững chắc. Ngược lại, một container được khởi chạy với `--privileged`, chia sẻ PID/network của host, mount Docker socket bên trong và có bind mount `/` cho phép ghi, về mặt chức năng sẽ gần với quyền truy cập root trên host hơn là một sandbox ứng dụng được cô lập an toàn. Sự khác biệt nằm ở các lớp được bật hoặc tắt.

Ngoài ra còn có một lựa chọn trung gian mà người đọc nên hiểu, vì nó ngày càng phổ biến trong môi trường thực tế. **Sandboxed container runtime** như **gVisor** và **Kata Containers** cố ý tăng cường ranh giới bảo vệ hơn so với container `runc` thông thường. gVisor đặt một lớp kernel userspace giữa workload và nhiều giao diện kernel của host, trong khi Kata khởi chạy workload bên trong một máy ảo nhẹ. Chúng vẫn được sử dụng thông qua hệ sinh thái container và quy trình điều phối, nhưng đặc tính bảo mật khác với runtime OCI thuần túy; không nên gộp chúng vào nhóm "Docker container thông thường" như thể mọi thứ hoạt động giống nhau.

## Stack Container: Nhiều Lớp, Không Phải Một

Khi ai đó nói "container này không an toàn", câu hỏi tiếp theo hữu ích là: **lớp nào khiến nó không an toàn?** Một workload chạy trong container thường là kết quả phối hợp của nhiều thành phần.

Ở tầng trên cùng thường có **lớp build image** như BuildKit, Buildah hoặc Kaniko, chịu trách nhiệm tạo image OCI và metadata. Phía trên runtime cấp thấp có thể có **engine hoặc trình quản lý** như Docker Engine, Podman, containerd, CRI-O, Incus hoặc systemd-nspawn. Trong môi trường cluster, cũng có thể có **orchestrator** như Kubernetes quyết định trạng thái bảo mật được yêu cầu thông qua cấu hình workload. Cuối cùng, **kernel** là thành phần thực thi namespaces, cgroups, seccomp và chính sách MAC.

Mô hình nhiều lớp này rất quan trọng để hiểu các cấu hình mặc định. Một giới hạn có thể được yêu cầu bởi Kubernetes, được containerd hoặc CRI-O chuyển đổi thông qua CRI, được wrapper runtime chuyển thành OCI spec, rồi mới được `runc`, `crun`, `runsc` hoặc runtime khác thực thi trên kernel. Khi cấu hình mặc định khác nhau giữa các môi trường, thường là do một trong các lớp này đã thay đổi cấu hình cuối cùng. Vì vậy, cùng một cơ chế có thể xuất hiện dưới dạng cờ CLI trong Docker hoặc Podman, trường Pod hoặc `securityContext` trong Kubernetes, và cấu hình OCI được tạo cho workload trong stack runtime cấp thấp hơn. Do đó, các ví dụ CLI trong phần này nên được hiểu là **cú pháp riêng của runtime cho một khái niệm container tổng quát**, chứ không phải cờ dùng chung được mọi công cụ hỗ trợ.

## Ranh Giới Bảo Mật Thực Sự Của Container

Trên thực tế, bảo mật container đến từ **các biện pháp kiểm soát chồng lớp**, chứ không phải một biện pháp hoàn hảo duy nhất. Namespace cô lập những gì có thể nhìn thấy. cgroups quản lý và giới hạn mức sử dụng tài nguyên. Capability hạn chế những gì một tiến trình trông có vẻ đặc quyền thực sự có thể làm. seccomp chặn syscall nguy hiểm trước khi chúng đến kernel. AppArmor và SELinux bổ sung Mandatory Access Control bên trên các kiểm tra DAC thông thường. `no_new_privs`, các đường dẫn procfs bị che và đường dẫn hệ thống chỉ đọc khiến những chuỗi lạm dụng quyền và proc/sys phổ biến khó thực hiện hơn. Bản thân runtime cũng quan trọng vì nó quyết định cách tạo mount, socket, nhãn và việc tham gia namespace.

Đó là lý do nhiều tài liệu về bảo mật container có vẻ lặp lại. Cùng một chuỗi escape thường phụ thuộc đồng thời vào nhiều cơ chế. Ví dụ, bind mount host cho phép ghi vốn đã nguy hiểm, nhưng sẽ nguy hiểm hơn nhiều nếu container cũng chạy với quyền root thực sự trên host, có `CAP_SYS_ADMIN`, không bị seccomp giới hạn và không bị SELinux hoặc AppArmor hạn chế. Tương tự, chia sẻ PID của host là một rủi ro nghiêm trọng, nhưng trở nên hữu ích hơn đáng kể đối với kẻ tấn công khi kết hợp với `CAP_SYS_PTRACE`, cơ chế bảo vệ procfs yếu hoặc công cụ vào namespace như `nsenter`. Vì vậy, cách phù hợp để ghi chép chủ đề này không phải là lặp lại cùng một cuộc tấn công trên mọi trang, mà là giải thích từng lớp đóng góp gì vào ranh giới bảo vệ cuối cùng.

## Cách Đọc Phần Này

Phần này được sắp xếp từ các khái niệm tổng quát nhất đến các khái niệm cụ thể nhất.

Bắt đầu với phần tổng quan về runtime và hệ sinh thái:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Sau đó xem xét các control plane và bề mặt supply chain thường quyết định liệu kẻ tấn công có cần kernel escape hay không:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Tiếp theo, tìm hiểu mô hình bảo vệ:

{{#ref}}
protections/
{{#endref}}

Các trang về namespace giải thích riêng từng cơ chế cô lập của kernel:

{{#ref}}
protections/namespaces/
{{#endref}}

Các trang về cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, đường dẫn bị che và đường dẫn hệ thống chỉ đọc giải thích những cơ chế thường được xếp thêm bên trên namespace:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Tư Duy Khảo Sát Ban Đầu Hiệu Quả

Khi đánh giá mục tiêu chạy trong container, việc đặt một nhóm câu hỏi kỹ thuật chính xác sẽ hữu ích hơn nhiều so với việc lập tức tìm đến các PoC escape nổi tiếng. Trước tiên, hãy xác định **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer hay một nền tảng chuyên biệt khác. Sau đó xác định **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` hay một triển khai tương thích OCI khác. Tiếp theo, kiểm tra môi trường là **rootful hay rootless**, **user namespace** có hoạt động hay không, có chia sẻ **namespace của host** nào không, còn lại những **capability** nào, **seccomp** có được bật không, **chính sách MAC** có thực sự được thực thi không, có **mount hoặc socket nguy hiểm** nào không, và tiến trình có thể tương tác với API của container runtime hay không.

Những câu trả lời đó cho bạn biết về trạng thái bảo mật thực tế nhiều hơn tên image nền tảng. Trong nhiều lần đánh giá, chỉ cần hiểu cấu hình cuối cùng của container là bạn có thể dự đoán nhóm breakout có khả năng xảy ra trước cả khi đọc một tệp ứng dụng nào.

## Phạm Vi

Phần này sắp xếp lại nội dung cũ tập trung vào Docker theo hướng lấy container làm trọng tâm: lộ diện runtime và daemon, plugin ủy quyền, độ tin cậy của image và build secret, mount host nhạy cảm, workload distroless, container đặc quyền và các biện pháp bảo vệ kernel thường được xếp lớp quanh quá trình thực thi container.

{{#include ../../../banners/hacktricks-training.md}}
