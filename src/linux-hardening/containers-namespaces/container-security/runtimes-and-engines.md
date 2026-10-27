# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Một trong những nguyên nhân lớn nhất gây nhầm lẫn về bảo mật container là nhiều thành phần hoàn toàn khác nhau thường bị gộp vào cùng một từ. “Docker” có thể chỉ định dạng image, CLI, daemon, hệ thống build, runtime stack hoặc đơn giản là khái niệm container nói chung. Trong công việc bảo mật, sự mơ hồ đó là một vấn đề, vì các lớp khác nhau chịu trách nhiệm cho những biện pháp bảo vệ khác nhau. Một vụ breakout do bind mount cấu hình sai không giống với breakout do lỗi ở low-level runtime, và cả hai cũng không giống lỗi chính sách cụm trong Kubernetes.

Trang này phân tách hệ sinh thái theo vai trò để các phần còn lại có thể xác định chính xác biện pháp bảo vệ hoặc điểm yếu nằm ở đâu.

## OCI As The Common Language

Các Linux container stack hiện đại thường có thể tương tác với nhau vì chúng sử dụng một tập hợp đặc tả OCI. **OCI Image Specification** mô tả cách biểu diễn image và layer. **OCI Runtime Specification** mô tả cách runtime khởi chạy tiến trình, bao gồm namespace, mount, cgroup và thiết lập bảo mật. **OCI Distribution Specification** tiêu chuẩn hóa cách registry cung cấp nội dung.

Điều này lý giải vì sao image container được build bằng một công cụ thường có thể chạy bằng công cụ khác, và vì sao nhiều engine có thể dùng chung low-level runtime. Điều này cũng lý giải vì sao hành vi bảo mật có thể giống nhau ở các sản phẩm khác nhau: nhiều sản phẩm trong số đó tạo cùng một cấu hình OCI runtime rồi chuyển cấu hình đó cho một trong số ít runtime hiện có.

## Low-Level OCI Runtimes

Low-level runtime là thành phần gần ranh giới kernel nhất. Đây là phần thực sự tạo namespace, ghi thiết lập cgroup, áp dụng capability và bộ lọc seccomp, rồi cuối cùng gọi `execve()` để chạy tiến trình container. Khi thảo luận về “container isolation” ở cấp cơ chế, mọi người thường đang nói đến lớp này, dù không nói rõ.

### `runc`

`runc` là OCI runtime tham chiếu và vẫn là triển khai được biết đến rộng rãi nhất. Nó được sử dụng nhiều bên dưới Docker, containerd và nhiều bản triển khai Kubernetes. Phần lớn nghiên cứu công khai và tài liệu khai thác nhắm đến các môi trường kiểu `runc` đơn giản vì chúng phổ biến, đồng thời `runc` xác định chuẩn cơ sở mà nhiều người hình dung khi nghĩ về Linux container. Vì vậy, hiểu `runc` giúp người đọc xây dựng mô hình tư duy vững chắc về container isolation cổ điển.

### `crun`

`crun` là một OCI runtime khác, được viết bằng C và được sử dụng rộng rãi trong các môi trường Podman hiện đại. Runtime này thường được đánh giá cao nhờ hỗ trợ cgroup v2 tốt, khả năng sử dụng rootless thuận tiện và overhead thấp hơn. Từ góc độ bảo mật, điều quan trọng không phải là nó được viết bằng ngôn ngữ khác, mà là nó vẫn đảm nhiệm cùng vai trò: chuyển cấu hình OCI thành cây tiến trình đang chạy bên dưới kernel. Quy trình làm việc rootless với Podman thường có vẻ an toàn hơn, không phải vì `crun` tự động khắc phục mọi vấn đề, mà vì stack tổng thể xung quanh nó thường ưu tiên user namespace và least privilege hơn.

### `runsc` From gVisor

`runsc` là runtime được gVisor sử dụng. Ở đây, ranh giới thay đổi đáng kể. Thay vì chuyển trực tiếp hầu hết syscall đến host kernel theo cách thông thường, gVisor chèn một lớp kernel userspace để mô phỏng hoặc trung gian xử lý phần lớn giao diện Linux. Kết quả không phải là container `runc` thông thường với vài flag bổ sung; đây là một thiết kế sandbox khác nhằm giảm bề mặt tấn công của host kernel. Các đánh đổi về khả năng tương thích và hiệu năng là một phần của thiết kế này, vì vậy cần ghi lại các môi trường dùng `runsc` khác với môi trường OCI runtime thông thường.

### `kata-runtime`

Kata Containers đẩy ranh giới xa hơn bằng cách chạy workload bên trong một máy ảo nhẹ. Về mặt quản trị, môi trường này có thể vẫn giống như một bản triển khai container, và các lớp điều phối có thể vẫn xem nó là container, nhưng ranh giới isolation bên dưới gần với ảo hóa hơn là container cổ điển dùng chung host kernel. Điều này khiến Kata hữu ích khi cần isolation tenant mạnh hơn mà không phải từ bỏ quy trình làm việc tập trung vào container.

## Engines And Container Managers

Nếu low-level runtime là thành phần giao tiếp trực tiếp với kernel, thì engine hoặc manager là thành phần mà người dùng và quản trị viên thường tương tác. Nó xử lý việc tải image, metadata, log, mạng, volume, thao tác vòng đời và cung cấp API. Lớp này rất quan trọng vì nhiều vụ xâm nhập thực tế xảy ra ở đây: quyền truy cập vào runtime socket hoặc daemon API có thể tương đương với việc chiếm quyền host, ngay cả khi bản thân low-level runtime hoạt động hoàn toàn bình thường.

### Docker Engine

Docker Engine là nền tảng container dễ nhận diện nhất đối với developer và là một trong những lý do khiến từ vựng về container mang đậm dấu ấn Docker. Quy trình thông thường là từ CLI `docker` đến `dockerd`, sau đó daemon điều phối các thành phần cấp thấp hơn như `containerd` và một OCI runtime. Trong lịch sử, các bản triển khai Docker thường **rootful**, vì vậy quyền truy cập vào Docker socket là một primitive rất mạnh. Đây là lý do nhiều tài liệu thực tiễn về leo thang đặc quyền tập trung vào `docker.sock`: nếu một tiến trình có thể yêu cầu `dockerd` tạo container đặc quyền, mount đường dẫn host hoặc tham gia host namespace, có thể nó không cần khai thác kernel.

So sánh số phiên bản theo thành phần major, minor và patch thay vì bỏ dấu chấm: `18.09.1` cũ hơn cả `18.09.2` và `18.09.4`, dù thành phần minor của nó có số 0 ở đầu. [Ghi chú phát hành Docker 18.09](https://docs.docker.com/engine/release-notes/18.09/) ghi nhận bản sửa lỗi `runc` đi kèm cho CVE-2019-5736 trong 18.09.2 và bản sửa lỗi build-reference cho CVE-2019-13139 trong 18.09.4. Đây là manh mối về phiên bản, không phải bằng chứng rằng có thể khai thác được. Cùng ghi chú phát hành cũng cảnh báo rằng daemon, client và runtime được đóng gói riêng, vì vậy hãy kiểm tra runtime đã cài đặt và các bản vá backport của nhà cung cấp cùng với phiên bản daemon; lỗi build-reference cũng đòi hỏi quyền truy cập vào quy trình build bị ảnh hưởng và dữ liệu đầu vào do kẻ tấn công kiểm soát.

### Podman

Podman được thiết kế theo mô hình không cần daemon hơn. Về vận hành, cách này giúp củng cố quan niệm rằng container chỉ là các tiến trình được quản lý thông qua những cơ chế Linux tiêu chuẩn, thay vì thông qua một daemon đặc quyền chạy lâu dài. Podman cũng hỗ trợ **rootless** tốt hơn nhiều so với các bản triển khai Docker cổ điển mà nhiều người thường làm quen đầu tiên. Điều đó không khiến Podman tự động an toàn, nhưng nó thay đổi đáng kể hồ sơ rủi ro mặc định, đặc biệt khi kết hợp với user namespace, SELinux và `crun`.

### containerd

containerd là thành phần quản lý runtime cốt lõi trong nhiều stack hiện đại. Nó được dùng bên dưới Docker và cũng là một trong những backend runtime Kubernetes phổ biến nhất. Nó cung cấp API mạnh, quản lý image và snapshot, đồng thời giao việc tạo tiến trình cuối cùng cho low-level runtime. Khi thảo luận về bảo mật containerd, cần nhấn mạnh rằng quyền truy cập vào socket containerd hoặc chức năng `ctr`/`nerdctl` có thể nguy hiểm ngang với quyền truy cập Docker API, ngay cả khi giao diện và quy trình có vẻ ít “thân thiện với developer” hơn.

### CRI-O

CRI-O có phạm vi tập trung hơn Docker Engine. Thay vì là nền tảng đa dụng cho developer, nó được xây dựng để triển khai Kubernetes Container Runtime Interface một cách gọn gàng. Vì vậy, nó đặc biệt phổ biến trong các bản phân phối Kubernetes và hệ sinh thái chú trọng SELinux như OpenShift. Từ góc độ bảo mật, phạm vi hẹp hơn này rất hữu ích vì giảm sự phức tạp về khái niệm: CRI-O rõ ràng thuộc lớp “chạy container cho Kubernetes” hơn là một nền tảng đa năng.

Khi một node Kubernetes sử dụng CRI-O, hãy kiểm tra **bản phát hành CRI-O đang hoạt động trên node** cùng với việc danh tính hiện tại có thể tạo Pod trong namespace được lập lịch trên node đó hay không. [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) cho phép các giá trị sysctl được tạo thủ công trong Pod thay đổi tham số kernel của host và dẫn đến thực thi với quyền root trên host ở các bản phát hành bị ảnh hưởng. Advisory của upstream liệt kê các bản phát hành đã vá và cách khắc phục. Lệnh `crio --version` cục bộ có thể không phát hiện runtime nằm bên trong Minikube hoặc container node khác; log khởi động Minikube có thể đọc được sẽ cung cấp manh mối về phiên bản, nhưng đó là bằng chứng lịch sử, không phải bằng chứng về runtime đang hoạt động hoặc trạng thái vá lỗi của nó. Hãy xác nhận runtime thực tế của node, quyền tạo Pod, quy tắc admission và các ranh giới seccomp cũng như user namespace liên quan trước khi xem đây là một đường leo thang có thể khai thác.

Ngoài ra còn có quy trình kiểm tra `pinns` trực tiếp trên máy cục bộ: [các nhà nghiên cứu phát hiện ra rằng không cần Kubernetes để gọi helper có lỗi](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). Hãy kiểm tra liệu tài khoản hiện tại có thể thực thi `pinns` thuộc quyền sở hữu của root và có bit setuid hay không, liệu NoNewPrivs hoặc mount `nosuid` có chặn việc chuyển đổi đó hay không, và **bản build của helper đã cài đặt** có thiếu bản sửa lỗi hay không. [Advisory của upstream](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) liệt kê các phiên bản đã vá, nhưng chỉ riêng phiên bản hiển thị của daemon không chứng minh được binary helper nào đang được cài đặt; các bản backport của nhà phân phối cũng có thể làm thay đổi mức độ ảnh hưởng. File setuid chỉ là một đối tượng cần kiểm tra; hãy xác minh nguồn gốc của helper, cấu hình và hành vi sysctl của host mà không chạy helper trong quá trình rà soát thông thường.

### Incus, LXD, And LXC

Cần phân biệt hệ thống Incus/LXD/LXC với application container kiểu Docker vì chúng thường được dùng làm **system container**. System container thường được kỳ vọng hoạt động giống một máy nhẹ hơn, với userspace đầy đủ hơn, các dịch vụ chạy lâu dài, khả năng hiển thị thiết bị phong phú hơn và tích hợp host sâu hơn. Các cơ chế isolation vẫn là primitive của kernel, nhưng kỳ vọng vận hành khác nhau. Vì vậy, lỗi cấu hình ở đây thường giống sai sót trong ảo hóa nhẹ hoặc ủy quyền cho host hơn là “thiết lập mặc định không tốt của app container”.

### systemd-nspawn

systemd-nspawn có vị trí đáng chú ý vì tích hợp tự nhiên với systemd và rất hữu ích cho việc kiểm thử, gỡ lỗi và chạy các môi trường giống hệ điều hành. Đây không phải runtime cloud-native dùng phổ biến nhất trong production, nhưng xuất hiện đủ thường xuyên trong lab và các môi trường tập trung vào distro để đáng được nhắc đến. Trong phân tích bảo mật, đây là lời nhắc thêm rằng khái niệm “container” bao gồm nhiều hệ sinh thái và kiểu vận hành khác nhau.

### Apptainer / Singularity

Apptainer (trước đây là Singularity) phổ biến trong môi trường nghiên cứu và HPC. Các giả định về độ tin cậy, quy trình làm việc của người dùng và mô hình thực thi của nó khác đáng kể so với stack tập trung vào Docker/Kubernetes. Đặc biệt, các môi trường này thường rất chú trọng việc cho phép người dùng chạy workload được đóng gói mà không cấp cho họ quyền quản lý container đặc quyền ở phạm vi rộng. Nếu người đánh giá mặc định mọi môi trường container về cơ bản đều là “Docker trên server”, họ sẽ hiểu sai nghiêm trọng các bản triển khai này.

## Build-Time Tooling

Nhiều cuộc thảo luận về bảo mật chỉ nói đến thời gian chạy, nhưng công cụ build cũng quan trọng vì nó quyết định nội dung image, nguy cơ lộ build secret và mức độ ngữ cảnh đáng tin cậy được nhúng vào artifact cuối cùng.

**BuildKit** và `docker buildx` là các backend build hiện đại hỗ trợ những tính năng như caching, mount secret, chuyển tiếp SSH và build đa nền tảng. Đây là những tính năng hữu ích, nhưng từ góc độ bảo mật, chúng cũng tạo ra những nơi secret có thể leak vào các image layer hoặc ngữ cảnh build quá rộng có thể làm lộ những file đáng lẽ không bao giờ được đưa vào. **Buildah** có vai trò tương tự trong các hệ sinh thái OCI-native, đặc biệt là quanh Podman, trong khi **Kaniko** thường được dùng trong môi trường CI không muốn cấp Docker daemon đặc quyền cho pipeline build.

Bài học chính là tạo image và thực thi image là hai giai đoạn khác nhau, nhưng một build pipeline yếu có thể làm suy giảm tư thế bảo mật khi chạy từ rất lâu trước lúc container được khởi chạy.

## Orchestration Is Another Layer, Not The Runtime

Không nên đồng nhất Kubernetes với chính runtime. Kubernetes là bộ điều phối. Nó lập lịch Pod, lưu trạng thái mong muốn và thể hiện chính sách bảo mật thông qua cấu hình workload. Sau đó, kubelet giao tiếp với một triển khai CRI như containerd hoặc CRI-O; triển khai này tiếp tục gọi low-level runtime như `runc`, `crun`, `runsc` hoặc `kata-runtime`.

Sự phân tách này rất quan trọng vì nhiều người nhầm lẫn gán một biện pháp bảo vệ cho “Kubernetes” trong khi biện pháp đó thực sự được node runtime thực thi, hoặc đổ lỗi cho “thiết lập mặc định của containerd” dù hành vi đó xuất phát từ Pod spec. Trên thực tế, tư thế bảo mật cuối cùng là kết quả tổng hợp: bộ điều phối đưa ra yêu cầu, runtime stack chuyển đổi yêu cầu đó, rồi kernel thực thi nó.

## Why Runtime Identification Matters During Assessment

Nếu xác định engine và runtime sớm, việc diễn giải nhiều quan sát sau đó sẽ dễ dàng hơn. Container Podman rootless cho thấy user namespace có thể là một phần của môi trường. Docker socket được mount vào workload cho thấy leo thang đặc quyền qua API là một đường đi thực tế. Node CRI-O/OpenShift nên khiến bạn nghĩ ngay đến nhãn SELinux và chính sách workload hạn chế. Môi trường gVisor hoặc Kata đòi hỏi bạn thận trọng hơn khi cho rằng PoC breakout kiểu `runc` cổ điển sẽ hoạt động tương tự.

Vì vậy, một trong những bước đầu tiên khi đánh giá container luôn phải là trả lời hai câu hỏi đơn giản: **thành phần nào đang quản lý container** và **runtime nào thực sự đã khởi chạy tiến trình**. Khi đã rõ các câu trả lời này, việc phân tích phần còn lại của môi trường thường sẽ dễ dàng hơn nhiều.

## Runtime Vulnerabilities

Không phải mọi vụ container escape đều bắt nguồn từ lỗi cấu hình của người vận hành. Đôi khi, chính runtime là thành phần có lỗ hổng. Điều này quan trọng vì workload có thể chạy với cấu hình tưởng như cẩn thận nhưng vẫn bị ảnh hưởng bởi lỗi ở low-level runtime.

Ví dụ kinh điển là **CVE-2019-5736** trong `runc`, khi container độc hại có thể ghi đè binary `runc` trên host rồi chờ lần gọi `docker exec` tiếp theo hoặc một thao tác tương tự của runtime để kích hoạt mã do kẻ tấn công kiểm soát. Đường khai thác này khác hẳn lỗi bind mount hoặc capability đơn giản vì nó lợi dụng cách runtime quay lại không gian tiến trình của container trong quá trình xử lý exec.<sup>[[1]](#references)</sup>

Quy trình tái hiện tối thiểu từ góc nhìn red-team là:

```bash
go build main.go
./main
```

Sau đó, từ host:

```bash
docker exec -it <container-name> /bin/sh
```

Bài học then chốt không nằm ở cách triển khai chính xác của exploit lịch sử, mà ở hệ quả khi đánh giá: nếu phiên bản runtime có lỗ hổng, việc thực thi mã thông thường bên trong container có thể đủ để xâm phạm host, ngay cả khi cấu hình container hiển thị không có vẻ yếu một cách rõ ràng.

Các CVE runtime gần đây như `CVE-2024-21626` trong `runc`, các race condition khi mount của BuildKit và lỗi phân tích cú pháp của containerd càng củng cố điểm này. Phiên bản runtime và mức độ vá lỗi là một phần của ranh giới bảo mật, chứ không chỉ là chi tiết bảo trì.

## References

- [1] [Thoát khỏi Docker thông qua runC – Giải thích CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
