# Kiểm tra Pcap

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> **PCAP** và **PCAPNG** là hai định dạng capture khác nhau; **PCAPNG là phiên bản kế nhiệm linh hoạt, có thể mở rộng của PCAP**, nhưng mức độ hỗ trợ tùy thuộc vào từng công cụ. Nếu công cụ không đọc được PCAPNG, hãy chuyển đổi sang PCAP bằng Wireshark hoặc một công cụ tương thích khác.<sup>[[1]](#references)[[18]](#references)</sup>

## Công cụ trực tuyến dành cho pcap

- Nếu header của pcap bị **hỏng**, bạn nên thử **sửa** bằng: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- Trích xuất **thông tin** và tìm kiếm **malware** bên trong pcap bằng [**PacketTotal**](https://packettotal.com).<sup>[[19]](#references)</sup>
- Tìm kiếm **hoạt động độc hại** bằng [**www.virustotal.com**](https://www.virustotal.com) và [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com).<sup>[[3]](#references)[[4]](#references)</sup>
- **Phân tích pcap đầy đủ ngay trên trình duyệt bằng** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## Trích xuất thông tin

Các công cụ sau hữu ích để trích xuất thống kê, tệp, v.v.

### Wireshark

> [!TIP]
> **Nếu bạn định phân tích PCAP thì về cơ bản, bạn phải biết cách sử dụng Wireshark**

Bạn có thể tìm thấy một số thủ thuật Wireshark tại:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Phân tích Pcap ngay trên trình duyệt.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) là một công cụ điều tra pháp chứng mạng dành cho Unix-like, có thể giải mã tệp PCAP và trích xuất email qua POP/IMAP/SMTP, nội dung HTTP, cuộc gọi SIP VoIP, dữ liệu FTP và dữ liệu TFTP.<sup>[[6]](#references)</sup>

**Cài đặt**

```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```

**Chạy**

```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```

Truy cập _**127.0.0.1:9876**_ bằng thông tin đăng nhập _**xplico:xplico**_

Sau đó tạo **case mới**, tạo **session mới** bên trong case và **upload** file **pcap**.

### NetworkMiner

Giống như Xplico, [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) phân tích lưu lượng PCAP để trích xuất các artifact như file, hình ảnh, email và mật khẩu, đồng thời tổng hợp thông tin về host; phiên bản miễn phí chủ yếu dành cho Windows.<sup>[[7]](#references)</sup>

### NetWitness Investigator

Bạn có thể tải [**NetWitness Investigator tại đây**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Công cụ chạy trên Windows)**.\
Nhà cung cấp mô tả phiên bản miễn phí là công cụ phân tích phiên mạng tương tác, dùng để sàng lọc hoạt động độc hại và hiện cung cấp quyền truy cập qua biểu mẫu liên hệ.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

Các module được ghi tài liệu của BruteShark có thể phân tích thông tin xác thực từ HTTP, FTP, Telnet, IMAP và SMTP; xuất hash xác thực Kerberos, NTLM, CRAM-MD5 và HTTP-Digest cho Hashcat; lập bản đồ các node và user trong mạng; trích xuất truy vấn DNS; dựng lại các session TCP/UDP; và trích xuất file.<sup>[[9]](#references)</sup>

### Capinfos

Theo mặc định, `capinfos` của Wireshark in báo cáo dài về một file capture.<sup>[[10]](#references)</sup>

```
capinfos capture.pcap
```

### Ngrep

`ngrep` tìm kiếm payload của packet bằng biểu thức chính quy và chấp nhận bộ lọc BPF; `-I` đọc tệp capture tương thích với pcap.<sup>[[11]](#references)</sup> Ví dụ kết hợp các tính năng này để tìm kiếm một HTTP request trong lưu lượng được chọn.

```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```

### Carving

Sử dụng các kỹ thuật carving phổ biến có thể hữu ích để trích xuất tệp và thông tin từ pcap:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Thu thập thông tin xác thực

Bạn có thể dùng [PCredz](https://github.com/lgandx/PCredz) để phân tích thông tin xác thực từ tệp PCAP đã lưu hoặc một interface trực tiếp.<sup>[[12]](#references)</sup>

## Kiểm tra Exploits/Malware

### Suricata

**Cài đặt và thiết lập**

```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```

**Kiểm tra pcap**

Tùy chọn `-r` của Suricata phát lại PCAP ở chế độ offline; trong ví dụ này, `-k none` tắt kiểm tra checksum, `-v` tăng mức ghi log và `-l` chọn thư mục log.<sup>[[13]](#references)</sup>

```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```

### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) xử lý các luồng HTTP từ tệp PCAP, tùy chọn giải nén các luồng gzip, quét các tệp được trích xuất bằng YARA, ghi `report.txt` và có thể lưu các tệp khớp vào một thư mục.<sup>[[14]](#references)</sup>

### Phân tích Malware

Kiểm tra xem bạn có thể tìm thấy dấu hiệu nhận dạng nào của malware đã biết không:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) là công cụ phân tích lưu lượng mạng thụ động, mã nguồn mở, được dùng làm Network Security Monitor (NSM) và để phân tích lưu lượng ở phạm vi rộng hơn, bao gồm đo lường hiệu suất và khắc phục sự cố.<sup>[[15]](#references)</sup>

Zeek tạo ra các log có cấu trúc thay vì tệp PCAP, vì vậy hãy dùng các công cụ phân tích log như `zeek-cut` để kiểm tra các log đó.<sup>[[15]](#references)[[16]](#references)</sup>

### Thông tin kết nối

Các ví dụ bên dưới dùng `zeek-cut` để chọn các trường có tên từ log TSV, sau đó dùng các công cụ Unix tiêu chuẩn để xếp hạng và đếm kết nối; RITA cũng có thể nhập log Zeek để phân tích kết nối kéo dài, beaconing và DNS tunneling.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
#Get info about longest connections (add "grep udp" to see only udp traffic)
#The longest connection might be of malware (constant reverse shell?)
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration | sort -nrk 7 | head -n 10

10.55.100.100   49778   65.52.108.225   443     tcp     -       86222.365445
10.55.100.107   56099   111.221.29.113  443     tcp     -       86220.126151
10.55.100.110   60168   40.77.229.82    443     tcp     -       86160.119664


#Improve the metrics by summing up the total duration time for connections that have the same destination IP and Port.
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += $5 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10

10.55.100.100   65.52.108.225   443     tcp     86222.4
10.55.100.107   111.221.29.113  443     tcp     86220.1
10.55.100.110   40.77.229.82    443     tcp     86160.1

#Get the number of connections summed up per each line
cat conn.log | zeek-cut id.orig_h id.resp_h duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2] += $3; count[$1 FS $2] += 1 } END{ for (key in arr) printf "%s%s%s%s%s\n", key, FS, count[key], FS, arr[key] }' | sort -nrk 4 | head -n 10

10.55.100.100   65.52.108.225   1       86222.4
10.55.100.107   111.221.29.113  1       86220.1
10.55.100.110   40.77.229.82    134       86160.1

#Check if any IP is connecting to 1.1.1.1
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | grep '1.1.1.1' | sort | uniq -c

#Get number of connections per source IP, dest IP and dest Port
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += 1 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10


# RITA
#Something similar can be done with the tool rita
rita show-long-connections -H --limit 10 zeek_logs

+---------------+----------------+--------------------------+----------------+
|   SOURCE IP   | DESTINATION IP | DSTPORT:PROTOCOL:SERVICE |    DURATION    |
+---------------+----------------+--------------------------+----------------+
| 10.55.100.100 | 65.52.108.225  | 443:tcp:-                | 23h57m2.3655s  |
| 10.55.100.107 | 111.221.29.113 | 443:tcp:-                | 23h57m0.1262s  |
| 10.55.100.110 | 40.77.229.82   | 443:tcp:-                | 23h56m0.1197s  |

#Get connections info from rita
rita show-beacons zeek_logs | head -n 10
Score,Source IP,Destination IP,Connections,Avg Bytes,Intvl Range,Size Range,Top Intvl,Top Size,Top Intvl Count,Top Size Count,Intvl Skew,Size Skew,Intvl Dispersion,Size Dispersion
1,192.168.88.2,165.227.88.15,108858,197,860,182,1,89,53341,108319,0,0,0,0
1,10.55.100.111,165.227.216.194,20054,92,29,52,1,52,7774,20053,0,0,0,0
0.838,10.55.200.10,205.251.194.64,210,69,29398,4,300,70,109,205,0,0,0,0
```

### Thông tin DNS

```bash
#Get info about each DNS request performed
cat dns.log | zeek-cut -c id.orig_h query qtype_name answers

#Get the number of times each domain was requested and get the top 10
cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -n 10

#Get all the IPs
cat dns.log | zeek-cut id.orig_h query | grep 'example\.com' | cut -f 1 | sort | uniq -c

#Sort the most common DNS record request (should be A)
cat dns.log | zeek-cut qtype_name | sort | uniq -c | sort -nr

#See top DNS domain requested with rita
rita show-exploded-dns -H --limit 10 zeek_logs
```

## Các thủ thuật phân tích pcap khác


{{#ref}}
dnscat-exfiltration.md
{{#endref}}


{{#ref}}
wifi-pcap-analysis.md
{{#endref}}


{{#ref}}
usb-keystrokes.md
{{#endref}}

## References

- [1] [Hướng dẫn người dùng Wireshark: Mở tệp capture](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - dịch vụ sửa chữa pcap / pcapng trực tuyến](https://f00l.de/hacking/pcapfix.php)
- [3] [Tổng quan về VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - Giới thiệu](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator bản miễn phí](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [Kho lưu trữ BruteShark](https://github.com/odedshimon/BruteShark)
- [10] [Tài liệu hướng dẫn `capinfos` của Wireshark](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [Tài liệu ngrep](https://ngrep.sourceforge.net/usage.html)
- [12] [Kho lưu trữ PCredz](https://github.com/lgandx/PCredz)
- [13] [Các tùy chọn dòng lệnh Suricata](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [Kho lưu trữ YaraPcap](https://github.com/kevthehermit/YaraPcap)
- [15] [Zeek là gì?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Hướng dẫn về log Zeek](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [Kho lưu trữ RITA](https://github.com/activecm/rita)
- [18] [Tài liệu về `editcap` của Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [Thông báo về PacketTotal Upload API](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
