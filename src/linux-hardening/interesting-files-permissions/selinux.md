# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux là hệ thống **Mandatory Access Control (MAC)** dựa trên nhãn. Trên thực tế, điều này có nghĩa là ngay cả khi các quyền DAC, group hoặc Linux capabilities có vẻ đủ để thực hiện một hành động, kernel vẫn có thể từ chối hành động đó vì **source context** không được phép truy cập **target context** với class/permission được yêu cầu.<sup>[[1]](#references)</sup>

Một context thường có dạng:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Từ góc độ privesc, `type` (domain đối với process, type đối với object) thường là trường quan trọng nhất:<sup>[[1]](#references)</sup>

- Một process chạy trong **domain** như `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- File và socket có một **type** như `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy quyết định một domain có thể đọc/ghi/thực thi/chuyển sang domain kia hay không

## Liệt kê nhanh

Nếu SELinux được bật, hãy liệt kê sớm vì nó có thể giải thích tại sao các đường dẫn privesc Linux phổ biến không hoạt động hoặc tại sao một wrapper đặc quyền bao quanh một công cụ SELinux “vô hại” lại thực sự rất quan trọng:<sup>[[1]](#references)</sup>

```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```

Các bước kiểm tra tiếp theo hữu ích:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>

```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```

Các phát hiện đáng chú ý:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Chế độ `Disabled` hoặc `Permissive` làm mất phần lớn giá trị của SELinux trong vai trò ranh giới bảo vệ.
- `unconfined_t` thường có nghĩa là SELinux đang hoạt động nhưng không thực sự hạn chế tiến trình đó.
- `default_t`, `file_t` hoặc nhãn rõ ràng không phù hợp trên các đường dẫn tùy chỉnh thường cho thấy việc gán nhãn sai hoặc triển khai chưa hoàn chỉnh.
- Các ghi đè cục bộ trong `file_contexts.local` được ưu tiên hơn các mặc định của policy, vì vậy hãy kiểm tra kỹ chúng.

## Phân tích policy

SELinux dễ bị tấn công hoặc bypass hơn nhiều khi bạn có thể trả lời hai câu hỏi:

1. **Domain hiện tại của tôi có thể truy cập những gì?**
2. **Tôi có thể chuyển sang những domain nào?**

Các công cụ hữu ích nhất cho việc này là `sepolicy` và **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>

```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```

Điều này đặc biệt hữu ích khi host sử dụng **confined users** thay vì ánh xạ mọi người dùng sang `unconfined_u`. Trong trường hợp đó, hãy tìm:<sup>[[3]](#references)</sup>

- ánh xạ người dùng qua `semanage login -l`
- các role được phép qua `semanage user -l`
- các admin domain có thể truy cập như `sysadm_t`, `secadm_t`, `webadm_t`
- các mục `sudoers` sử dụng `ROLE=` hoặc `TYPE=`

Nếu `sudo -l` có các mục như sau, SELinux là một phần của ranh giới đặc quyền:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Đồng thời kiểm tra xem `newrole` có khả dụng hay không:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` và `newrole` không tự động có thể bị khai thác, nhưng nếu một wrapper có đặc quyền hoặc quy tắc `sudoers` cho phép bạn chọn role/type phù hợp hơn, chúng sẽ trở thành các primitive leo thang đặc quyền có giá trị cao.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Kiểm tra các entrypoint chuyển tiếp có thể ghi

Đồ thị chuyển tiếp chỉ là manh mối về policy. Để biến nó thành một đường tấn công, hãy xác định type của executable đưa bạn vào một domain hữu ích hơn, rồi kiểm tra xem bạn có thể sửa executable mang label đó hoặc thay thế nó thông qua thư mục cha hay không.<sup>[[9]](#references)[[20]](#references)</sup> Một chuyển tiếp `execve` tự động cần có quy tắc `type_transition` phù hợp, quyền execute của domain nguồn, quyền `entrypoint` của domain đích và quyền chuyển tiếp giữa các domain.<sup>[[20]](#references)</sup> Domain đích có thể được cấp quyền truy cập SELinux, nhưng việc thực thi tự nó không thay đổi Linux UID; hãy kiểm tra riêng [SUID/SGID và ACL](suid-sgid-and-acl-triage.md).<sup>[[20]](#references)[[21]](#references)</sup>

Dùng type entrypoint được báo cáo để kiểm tra các quy tắc liên quan, sau đó kiểm tra đường dẫn và thư mục cha để xác định quyền ghi.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Đối chiếu loại entrypoint với đường dẫn thực tế của tệp thực thi. Kiểm tra DAC, ACL, quyền ghi SELinux trên tệp hoặc thư mục cha, nhãn của tệp và mọi boolean có điều kiện trước khi coi một policy edge là có thể tiếp cận.<sup>[[20]](#references)[[22]](#references)</sup> Nếu đường dẫn bị thay thế thay vì chỉnh sửa tại chỗ, hãy xác minh context của inode mới: nhãn hệ thống tệp được lưu dưới dạng extended attributes, và bản thay thế có thể không giữ loại entrypoint.<sup>[[21]](#references)</sup> Các chương trình nhận biết SELinux có thể yêu cầu chuyển đổi bằng `setexeccon`, vì vậy việc không có quy tắc `type_transition` tự động không loại trừ mọi khả năng chuyển đổi.<sup>[[20]](#references)</sup>

## Tệp, gán lại nhãn và các cấu hình sai có giá trị cao

Khác biệt quan trọng nhất về mặt vận hành giữa các công cụ SELinux phổ biến là:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: thay đổi nhãn tạm thời trên một đường dẫn cụ thể
- `semanage fcontext`: quy tắc đường dẫn-sang-nhãn bền vững
- `restorecon` / `setfiles`: áp dụng lại nhãn theo policy/mặc định

Điều này rất quan trọng trong quá trình privesc vì **gán lại nhãn không chỉ là thay đổi hình thức**. Nó có thể biến một tệp từ trạng thái "bị policy chặn" thành "có thể đọc/thực thi bởi một dịch vụ bị giới hạn với đặc quyền cao".<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Kiểm tra các quy tắc gán lại nhãn cục bộ và tình trạng sai lệch nhãn:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

Một chi tiết tinh tế nhưng hữu ích: `restorecon` thông thường **không phải lúc nào cũng khôi phục hoàn toàn nhãn đáng ngờ**. Nếu type đích nằm trong `customizable_types`, bạn có thể cần dùng `-F` để buộc đặt lại hoàn toàn. Từ góc độ tấn công, điều này giải thích vì sao một lệnh `chcon` bất thường đôi khi vẫn tồn tại sau khi dọn dẹp kiểu qua loa với câu “chúng ta đã chạy restorecon rồi”.<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

Các lệnh có giá trị cao cần tìm trong `sudo -l`, root wrappers, script tự động hóa hoặc capabilities của tệp:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Nếu xuất hiện một trong hai capability MAC, hãy đối chiếu thêm với [trang Linux capabilities](linux-capabilities.md); tài liệu Linux capabilities mô tả `cap_mac_admin` và `cap_mac_override` là các capability dành riêng cho Smack, vì vậy đừng cho rằng chỉ dựa vào tên của chúng là có thể bypass SELinux.<sup>[[5]](#references)</sup>

Đặc biệt đáng chú ý:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: thay đổi lâu dài label mà một đường dẫn sẽ nhận
- `restorecon` / `setfiles`: áp dụng lại các thay đổi đó trên quy mô lớn
- `semodule -i`: tải một policy module tùy chỉnh
- `semanage permissive -a <domain_t>`: chuyển một domain sang chế độ permissive mà không chuyển toàn bộ host sang chế độ này
- `setsebool -P`: thay đổi lâu dài các policy boolean
- `load_policy`: tải lại policy đang hoạt động

Đây thường là các **primitive hỗ trợ**, không phải root exploit độc lập. Giá trị của chúng nằm ở chỗ cho phép bạn:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- chuyển domain mục tiêu sang chế độ permissive
- mở rộng quyền truy cập giữa domain của bạn và một type được bảo vệ
- đổi label các file do attacker kiểm soát để một service có đặc quyền có thể đọc hoặc thực thi chúng
- làm suy yếu một service bị giới hạn đủ để khai thác một lỗi cục bộ hiện có

Các bước kiểm tra mẫu:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

Nếu bạn có thể nạp một mô-đun policy với quyền root, bạn thường kiểm soát được ranh giới SELinux:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

Đó là lý do `audit2allow`, `semodule` và `semanage permissive` nên được xem là các bề mặt quản trị nhạy cảm trong quá trình post-exploitation. Chúng có thể âm thầm biến một chuỗi bị chặn thành chuỗi hoạt động được mà không thay đổi quyền UNIX cổ điển.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Hidden Denials and Module Extraction

Một vấn đề rất thường gặp trong các hoạt động tấn công là một chuỗi thất bại với lỗi `EACCES` chung chung, trong khi thông báo AVC denial mong đợi lại không xuất hiện. Các quy tắc `dontaudit` có thể đang che giấu chính xác quyền bạn cần. Nếu có thể chạy `semodule` thông qua `sudo` hoặc một wrapper có đặc quyền khác, tạm thời vô hiệu hóa `dontaudit` có thể biến một lỗi im lặng thành manh mối chính sách rõ ràng:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

Điều này cũng hữu ích khi xem xét những thay đổi mà quản trị viên cục bộ đã thực hiện. Một module tùy chỉnh nhỏ hoặc một quy tắc permissive áp dụng cho một domain thường là lý do khiến dịch vụ mục tiêu hoạt động lỏng lẻo hơn nhiều so với những gì policy cơ sở gợi ý.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Dấu hiệu kiểm tra

Các lệnh từ chối AVC thường là tín hiệu hữu ích cho tấn công, chứ không chỉ là nhiễu phòng thủ. Chúng cho bạn biết:<sup>[[1]](#references)[[15]](#references)</sup>

- bạn đã tác động đến object/type mục tiêu nào
- permission nào bị từ chối
- hiện tại bạn kiểm soát domain nào
- liệu một thay đổi nhỏ trong policy có giúp chuỗi tấn công hoạt động hay không

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Nếu một local exploit hoặc nỗ lực persistence liên tục thất bại với `EACCES` hoặc các lỗi "permission denied" khó hiểu dù quyền DAC trông như của root, bạn nên kiểm tra SELinux trước khi loại bỏ vector này.<sup>[[1]](#references)</sup>

## Người dùng SELinux

Ngoài người dùng Linux thông thường còn có người dùng SELinux. Theo policy, mỗi người dùng Linux được ánh xạ tới một người dùng SELinux, cho phép hệ thống áp dụng các role và domain được phép khác nhau cho từng tài khoản.<sup>[[3]](#references)</sup>

Kiểm tra nhanh:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Trên nhiều hệ thống phổ biến, người dùng được ánh xạ tới `unconfined_u`, làm giảm tác động thực tế của việc giới hạn người dùng. Tuy nhiên, trên các bản triển khai được harden, người dùng bị giới hạn có thể khiến `sudo`, `su`, `newrole` và `runcon` trở nên đáng chú ý hơn nhiều, vì **đường dẫn leo thang đặc quyền có thể phụ thuộc vào việc chuyển sang SELinux role/type có quyền cao hơn, chứ không chỉ trở thành UID 0**. Cũng cần nhớ rằng một số người dùng bị giới hạn không thể gọi `sudo`/`su` nếu policy không cho phép rõ ràng quá trình chuyển tiếp setuid bên dưới, vì vậy một host dùng `staff_u` + `sysadm_r` có thể biến một quy tắc `sudo ROLE=` / `TYPE=` tưởng như nhỏ thành ranh giới đặc quyền thực sự.<sup>[[3]](#references)</sup>

## SELinux trong Containers

Các container runtime thường khởi chạy workload trong một domain bị giới hạn như `container_t` và gắn nhãn nội dung container là `container_file_t`. Nếu một process trong container thoát ra nhưng vẫn chạy với nhãn container, thao tác ghi lên host vẫn có thể thất bại vì ranh giới nhãn vẫn được giữ nguyên.<sup>[[1]](#references)[[17]](#references)</sup>

Ví dụ nhanh:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

Phần `c647,c780` không phải để trang trí. Trong nhiều triển khai container, runtime tự động gán các category MCS để hai tiến trình chạy dưới dạng `container_t` vẫn được cách ly với nhau. Nếu một cuộc escape đưa bạn vào host namespace nhưng vẫn giữ nguyên tập category ban đầu, sự không khớp category vẫn có thể giải thích vì sao một số đường dẫn trên host vẫn không đọc hoặc ghi được.<sup>[[17]](#references)</sup>

Các thao tác container hiện đại đáng lưu ý:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` tắt tính năng cách ly bằng SELinux label cho container
- bind mount với `:z` / `:Z` kích hoạt việc gán lại label cho đường dẫn trên host để dùng chung/riêng với container
- việc gán lại label trên diện rộng cho nội dung host có thể tự nó trở thành vấn đề bảo mật

Trang này trình bày ngắn gọn phần nội dung về container để tránh trùng lặp. Để xem các trường hợp lạm dụng và ví dụ runtime dành riêng cho container, hãy tham khảo:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Tài liệu Red Hat: Sử dụng SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Công cụ phân tích policy cho SELinux](https://github.com/SELinuxProject/setools)
- [3] [Quản lý người dùng bị giới hạn và không bị giới hạn - Tài liệu RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Tài liệu chạy Podman](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Vì sao bạn nên dùng Multi-Category Security cho container Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Tài liệu podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [Sổ tay SELinux: Chuyển đổi domain và object](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: Sử dụng SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [Tài liệu hướng dẫn SETools sesearch(1)](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
