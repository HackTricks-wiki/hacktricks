# Bảng mẹo Suricata & Iptables

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

Trong iptables, mỗi chain là một danh sách tuần tự các quy tắc khớp gói tin. Bảng `filter` mặc định có các chain tích hợp `INPUT`, `FORWARD` và `OUTPUT`; các bảng khác, chẳng hạn như `nat`, có thể khả dụng tùy thuộc vào cấu hình kernel và các module đã tải.<sup>[[1]](#references)</sup>

- **Chuỗi Input**: Được sử dụng để quản lý cách xử lý các kết nối đến.
- **Chuỗi Forward**: Được sử dụng để xử lý các kết nối đến không hướng đến hệ thống cục bộ. Trường hợp này thường gặp ở các thiết bị hoạt động như router, nơi dữ liệu nhận được cần được chuyển tiếp đến một đích khác. Chain này chủ yếu liên quan khi hệ thống thực hiện routing, NAT hoặc các hoạt động tương tự.
- **Chuỗi Output**: Dùng để điều tiết các kết nối đi.

Các chain này đảm bảo lưu lượng mạng được xử lý theo trình tự, cho phép xác định các quy tắc chi tiết chi phối luồng dữ liệu đi vào, đi qua và đi ra khỏi hệ thống.

Các ví dụ khớp chuỗi sử dụng kiểu khớp `string` tiêu chuẩn; việc khớp phân biệt chữ hoa chữ thường trừ khi có `--icase`, còn `--algo` chọn chiến lược tìm kiếm BM hoặc KMP.<sup>[[2]](#references)</sup>

```bash
# Delete all rules
iptables -F

# List all rules
iptables -L
iptables -S

# Block IP addresses & ports
iptables -I INPUT -s ip1,ip2,ip3 -j DROP
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -s ip1,ip2 -p tcp --dport 443 -j DROP

# String based drop
## Strings are case sensitive (pretty easy to bypass if you want to check an SQLi for example)
iptables -I INPUT -p tcp --dport <port_listening> -m string --algo bm --string '<payload>' -j DROP
iptables -I OUTPUT -p tcp --sport <port_listening> -m string --algo bm --string 'CTF{' -j DROP
## You can also check for the hex, base64 and double base64 of the expected CTF flag chars

# Drop every input port except some
iptables -P INPUT DROP # Default to drop
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT


# Persist Iptables
## Debian/Ubuntu:
apt-get install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
iptables-restore < /etc/iptables/rules.v4
##RHEL/CentOS:
iptables-save > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables
iptables-restore < /etc/sysconfig/iptables
```

## Suricata

### Cài đặt & Cấu hình

Các lệnh cài đặt gói bên dưới tùy thuộc vào bản phân phối và phiên bản; hướng dẫn cài đặt chính thức có tài liệu về Ubuntu PPA, Debian backports, các gói RPM và cách quản lý dịch vụ systemd.<sup>[[3]](#references)</sup>

```bash
# Package installation details vary by distribution and release; see References.
# Ubuntu
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata

# Debian
echo "deb http://http.debian.net/debian buster-backports main" > \
    /etc/apt/sources.list.d/backports.list
apt-get update
apt-get install suricata -t buster-backports

# CentOS
yum install epel-release
yum install suricata

# Get rules
suricata-update update-sources
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl start suricata
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure Suricata as an IPS
## Config drop to generate alerts
## Search for the following lines in /etc/suricata/suricata.yaml and remove comments:
- drop:
    alerts: yes
    flows: all

## Forward all packages to the queue where suricata can act as IPS
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE

## Start suricata in IPS mode
suricata -c /etc/suricata/suricata.yaml  -q 0
### or modify the service config file as:
systemctl edit suricata.service

[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -q 0 -vvv
Type=simple

systemctl daemon-reload
```

Chuỗi `suricata-update` tuân theo quy trình được Suricata tài liệu hóa để tải, liệt kê, bật và nạp các nguồn rule.<sup>[[4]](#references)</sup> Lệnh `suricatasc` ở trên là phương thức tải lại rule qua Unix socket không chặn đã được tài liệu hóa.<sup>[[8]](#references)</sup> Các rule NFQUEUE chuyển lưu lượng đầu vào/đầu ra cục bộ đến Suricata, trong khi `-q 0` chọn queue 0 để xử lý inline.<sup>[[7]](#references)</sup>

### Định nghĩa Rules

Một rule/signature của Suricata có ba phần.<sup>[[5]](#references)</sup>

- **Action** chỉ định điều gì xảy ra khi signature khớp.
- **Header** chọn protocol, địa chỉ IP, port và hướng.
- **Rule options** xác định các chi tiết cụ thể của điều kiện khớp.

```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```

#### **Các hành động hợp lệ**

- alert - tạo cảnh báo
- pass - dừng kiểm tra gói tin
- **drop** - loại bỏ gói tin và tạo cảnh báo
- **reject** - gửi lỗi RST/ICMP unreachable đến bên gửi gói tin khớp.
- rejectsrc - giống như _reject_
- rejectdst - gửi gói tin lỗi RST/ICMP đến bên nhận gói tin khớp.
- rejectboth - gửi gói tin lỗi RST/ICMP đến cả hai bên của cuộc giao tiếp.

#### **Giao thức**

- tcp (dành cho lưu lượng tcp)
- udp
- icmp
- ip (ip có nghĩa là ‘tất cả’ hoặc ‘bất kỳ’)
- _giao thức layer7_: http, ftp, tls, smb, dns, ssh và các giao thức khác.<sup>[[5]](#references)</sup>

#### Địa chỉ nguồn và đích

Suricata hỗ trợ dải IP, phủ định và danh sách địa chỉ được nhóm.<sup>[[5]](#references)</sup>

| Ví dụ                         | Ý nghĩa                                   |
| ----------------------------- | ----------------------------------------- |
| ! 1.1.1.1                    | Mọi địa chỉ IP ngoại trừ 1.1.1.1          |
| !\[1.1.1.1, 1.1.1.2]          | Mọi địa chỉ IP ngoại trừ 1.1.1.1 và 1.1.1.2 |
| $HOME_NET                     | Giá trị HOME_NET bạn thiết lập trong yaml |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET nhưng không phải HOME_NET    |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 ngoại trừ 10.0.0.5            |

#### Cổng nguồn và đích

Suricata hỗ trợ dải cổng, phủ định và danh sách cổng.<sup>[[5]](#references)</sup>

| Ví dụ           | Ý nghĩa                                      |
| --------------- | -------------------------------------------- |
| any             | bất kỳ địa chỉ nào                           |
| \[80, 81, 82]   | cổng 80, 81 và 82                            |
| \[80: 82]       | Dải từ 80 đến 82                             |
| \[1024: ]       | Từ 1024 đến số cổng cao nhất                 |
| !80             | Mọi cổng ngoại trừ 80                        |
| \[80:100,!99]   | Dải từ 80 đến 100 nhưng loại trừ 99          |
| \[1:80,!\[2,4]] | Dải từ 1-80, ngoại trừ các cổng 2 và 4       |

#### Hướng

Quy tắc Suricata có thể chỉ định hướng giao tiếp được đánh giá.<sup>[[5]](#references)</sup>

```
source -> destination
source <> destination  (both directions)
```

#### Từ khóa

Các ví dụ dưới đây sử dụng các từ khóa rule của Suricata, bao gồm metadata, IP, ICMP, payload và các tùy chọn application layer; tài liệu rule chính thức liệt kê các nhóm này cùng cú pháp của chúng.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
# Meta Keywords
msg: "description"; #Set a description to the rule
sid:123 #Set a unique ID to the rule
rev:1 #Rule revision number
config classification: not-suspicious,Not Suspicious Traffic,3 #Classify
reference: url, www.info.com #Reference
priority:1; #Set a priority
metadata: key value, key value; #Extra metadata

# Filter by geolocation
geoip: src,RU;

# ICMP type & Code
itype:<10;
icode:0

# Filter by string
content: "something"
content: |61 61 61| #Hex: AAA
content: "http|3A|//" #Mix string and hex
content: "abc"; nocase; #Case insensitive
reject tcp any any -> any any (msg: "php-rce"; content: "eval"; nocase; metadata: tag php-rce; sid:101; rev: 1;)

# Replaces string
## Content and replace string must have the same length
## The replace modifier is IPS-only and operates on individual packets
content:"abc"; replace: "def"
alert tcp any any -> any any (msg: "flag replace"; content: "CTF{a6st"; replace: "CTF{u798"; nocase; sid:100; rev: 1;)
## The replace works in both input and output packets
## But it only modifies the first match

# Filter by regex
pcre:"/<regex>/opts"
pcre:"/NICK .*USA.*[0-9]{3,}/i"
drop tcp any any -> any any (msg:"regex"; pcre:"/CTF\{[\w]{3}/i"; sid:10001;)

# Other examples
## Drop by port
drop tcp any any -> any 8000 (msg:"8000 port"; sid:1000;)
```

## References

- [1] [iptables(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — trang hướng dẫn Linux](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Cài đặt — tài liệu Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Quản lý quy tắc bằng Suricata-Update — tài liệu Suricata 8.0.1](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Định dạng quy tắc — tài liệu Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Từ khóa Payload — tài liệu Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Thiết lập IPS/inline cho Linux — tài liệu Suricata 7.0.15](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Tải lại quy tắc — tài liệu Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Quy tắc Suricata — tài liệu Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
