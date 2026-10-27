# Phương pháp pháp chứng cơ bản

{{#include ../../banners/hacktricks-training.md}}

## Tạo và gắn kết ảnh

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Phân tích Malware

Đây **không nhất thiết là bước đầu tiên cần thực hiện sau khi có ảnh**. Tuy nhiên, bạn có thể áp dụng độc lập các kỹ thuật phân tích malware này nếu có một tệp, ảnh hệ thống tệp, ảnh bộ nhớ, pcap... vì vậy hãy **ghi nhớ những thao tác này**:

{{#ref}}
malware-analysis.md
{{#endref}}

## Kiểm tra ảnh

nếu được cung cấp **ảnh pháp chứng** của một thiết bị, bạn có thể bắt đầu **phân tích các phân vùng, hệ thống tệp** được sử dụng và **khôi phục** các **tệp có khả năng thú vị** (kể cả tệp đã xóa). Tìm hiểu cách thực hiện tại:

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Tùy vào hệ điều hành và thậm chí nền tảng được sử dụng, cần tìm kiếm các artifact đáng chú ý khác nhau:

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

{{#ref}}
ios-backup-forensics.md
{{#endref}}

Để biết về thiết bị Android bị khóa, các phương thức thu thập dữ liệu và tạo ảnh bộ nhớ, xem [Android forensics](android-forensics.md).

## Kiểm tra chuyên sâu các loại tệp và phần mềm cụ thể

Nếu bạn có một **tệp** rất **đáng ngờ**, thì tùy thuộc vào **loại tệp và phần mềm** tạo ra nó, một số **thủ thuật** có thể hữu ích.\
Đọc trang sau để tìm hiểu một số thủ thuật thú vị:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Tôi muốn đặc biệt nhắc đến trang:

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Kiểm tra Memory Dump

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Kiểm tra Pcap

{{#ref}}
pcap-inspection/
{{#endref}}

## **Kỹ thuật chống pháp chứng**

Hãy lưu ý đến khả năng các kỹ thuật chống pháp chứng đã được sử dụng:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Săn tìm mối đe dọa

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
