# Phân tích pcap DNSCat

{{#include ../../../banners/hacktricks-training.md}}

Nếu bạn có PCAP chứa dữ liệu đang được **exfiltrated bằng DNSCat** (không dùng mã hóa), bạn có thể khôi phục nội dung đã exfiltrated.

Đối với capture BSidesSF 2017 được nhắc đến bên dưới, bài phân tích suy luận rằng mỗi truy vấn đã giải mã bắt đầu bằng 9 byte dữ liệu riêng của dnscat, trước phần nội dung được truyền đi. Vì dnscat2 định nghĩa nhiều loại gói và bố cục header khác nhau, hãy xác minh cách đóng khung liên quan trước khi áp dụng độ lệch này cho lưu lượng khác.<sup>[[1]](#references)[[2]](#references)</sup>

```python
from scapy.all import rdpcap, DNSQR, DNSRR
import struct

f = ""
last = ""
for p in rdpcap('ch21.pcap'):
	if p.haslayer(DNSQR) and not p.haslayer(DNSRR):

		qry = p[DNSQR].qname.replace(".jz-n-bs.local.","").strip().split(".")
		qry = ''.join(_.decode('hex') for _ in qry)[9:]
		if last != qry:
			print(qry)
			f += qry
		last = qry

#print(f)
```

Để biết thêm thông tin, xem [bài viết BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) và [tài liệu giao thức dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

Repository [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) cung cấp một decoder Python 3 để trích xuất các luồng từ PCAP bằng cách lọc các truy vấn DNS theo một domain được chỉ định.<sup>[[3]](#references)</sup>

```
python3 dnscat_decoder.py sample.pcap bad_domain
```

## References

- [1] [tài liệu giao thức dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [bài viết phân tích pháp chứng pcap của DNSCat2 – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
