# Phân tích memory dump

{{#include ../../../banners/hacktricks-training.md}}

## Bắt đầu

Bắt đầu **tìm kiếm** **malware** trong pcap. Sử dụng các **công cụ** được đề cập trong [**Phân tích malware**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility là framework mã nguồn mở để phân tích memory dump**. Công cụ Python này phân tích các dump từ nguồn bên ngoài hoặc máy ảo VMware, xác định dữ liệu như tiến trình và mật khẩu dựa trên profile hệ điều hành của dump. Công cụ có thể mở rộng bằng plugin, nên rất linh hoạt cho các cuộc điều tra pháp chứng.<sup>[[1]](#references)[[2]](#references)</sup>

[**Xem cheatsheet tại đây**](volatility-cheatsheet.md)

## Báo cáo crash minidump

Khi dump có kích thước nhỏ (chỉ vài KB, có thể vài MB), đó có thể là báo cáo crash minidump thay vì memory dump đầy đủ.<sup>[[3]](#references)</sup>

![Volatility - Báo cáo crash minidump: Một tệp dump nhỏ được xác định là báo cáo crash Mini DuMP](<../../../images/image (532).png>)

Nếu đã cài Visual Studio, bạn có thể mở tệp này để xem thông tin cơ bản như tên tiến trình, kiến trúc, thông tin ngoại lệ và các module đã tải:<sup>[[4]](#references)</sup>

![Volatility - Báo cáo crash minidump: Nếu đã cài Visual Studio, bạn có thể mở tệp này và xem một số thông tin cơ bản như tên tiến trình, kiến trúc, thông tin ngoại lệ và...](<../../../images/image (263).png>)

Bạn cũng có thể kiểm tra ngoại lệ và xem disassembly của module.<sup>[[4]](#references)</sup>

![Bảng Actions của minidump trong Visual Studio với các tùy chọn debug native và thiết lập đường dẫn symbol](<../../../images/image (142).png>)

![Disassembly các lệnh từ ngoại lệ minidump trong Visual Studio](<../../../images/image (610).png>)

Dù vậy, Visual Studio không phải là công cụ tốt nhất để phân tích dump chuyên sâu.

Bạn nên **mở** tệp bằng **IDA** hoặc **Radare** để kiểm tra **chuyên sâu**.

## References

- [1] [Framework Volatility](https://github.com/volatilityfoundation/volatility)
- [2] [Cách sử dụng Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Tệp Minidump](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Sử dụng tệp dump trong trình debug của Visual Studio](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
