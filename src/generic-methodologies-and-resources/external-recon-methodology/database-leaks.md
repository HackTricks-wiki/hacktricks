# Leak cơ sở dữ liệu

{{#include ../../banners/hacktricks-training.md}}

## Công cụ tìm kiếm sự cố lộ dữ liệu

Để biết thông tin truy cập API và các lưu ý riêng của từng dịch vụ khi tìm kiếm dữ liệu về sự cố lộ dữ liệu hoặc danh tiếng, xem [Danh mục API Reconnaissance và Threat Intelligence](reconnaissance-and-threat-intelligence-apis.md).

- [GreyNoise Visualizer](https://viz.greynoise.io/) - Tra cứu IP và CIDR, đồng thời truy vấn hoạt động của scanner theo tag, CVE và metadata.<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - Tìm kiếm dữ liệu bị lộ theo tên người dùng, địa chỉ email, địa chỉ IP và các tiêu chí khác; dịch vụ cũng hỗ trợ giám sát và API.<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - Kiểm tra xem địa chỉ email có xuất hiện trong các vụ rò rỉ dữ liệu đã biết hoặc bản ghi paste hay không; dịch vụ cũng hỗ trợ thông báo và API.<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - Tìm kiếm hồ sơ kẻ lừa đảo được báo cáo theo ảnh đại diện, email, tên người dùng, số điện thoại, địa chỉ crypto hoặc website.<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - Tìm kiếm theo các tiêu chí như địa chỉ email, domain, URL, IP và CIDR trên các nguồn được lập chỉ mục.<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - Kiểm tra email công việc hoặc domain để tìm thông tin xác thực bị lộ, danh tính bị infostealer lây nhiễm và session cookie bị đánh cắp.<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - Tìm kiếm cơ sở dữ liệu bị leak theo domain, tên, email, ID, số điện thoại, IP, URL hoặc hash.<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - Kiểm tra xem email hoặc tên người dùng của bạn có bị xâm phạm hay không.
- [LeakCheck](https://leakcheck.io/) - Tìm kiếm dữ liệu email, tên người dùng, số điện thoại, hash hoặc domain bị lộ và giám sát các mục mới.<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - Tìm địa chỉ email thuộc một công ty.
- [Library of Leaks](https://search.libraryofleaks.org/) - Tìm kiếm tài liệu công khai, công ty và cá nhân, bao gồm cả các bộ dữ liệu leak.<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - Tìm kiếm thông tin xác thực bị leak theo email, domain hoặc chuỗi thô và giám sát các dữ liệu mới bị lộ.<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - Tìm kiếm log infostealer từ các thiết bị bị nhiễm và giám sát dữ liệu mới.<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - Tìm kiếm trong các vụ rò rỉ dữ liệu và giám sát thông tin xác thực bị lộ.<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - Công cụ tìm kiếm các vụ xâm phạm cơ sở dữ liệu do cộng đồng xây dựng.
- [Leaked.domains](https://leaked.domains/) - Tìm kiếm thông tin xác thực bị leak và các bản ghi liên quan theo domain, email, tên người dùng, mật khẩu, IP và các tiêu chí khác.<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - Giám sát hoạt động trên dark web, thông tin xác thực bị leak, dữ liệu infostealer và các lượt nhắc đến thương hiệu.<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Nền tảng tìm kiếm và giám sát dữ liệu dump từ Pastebin.

## Công cụ liệt kê data leak

- [Leaker](https://github.com/vflame6/leaker) - CLI tìm kiếm leak thụ động trên nhiều nguồn trực tuyến theo email, tên người dùng, domain, từ khóa hoặc số điện thoại.<sup>[[15]](#references)</sup>

## References

- [1] [Sử dụng GreyNoise Visualizer](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [Cơ sở dữ liệu kẻ lừa đảo toàn cầu - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [Kiểm tra mức độ lộ dữ liệu - SpyCloud](https://spycloud.com/check-your-exposure/)
- [7] [WeLeakInfo](https://weleakinfo.io/)
- [8] [Công cụ tìm kiếm sự cố rò rỉ dữ liệu - LeakCheck](https://leakcheck.io/)
- [9] [Library of Leaks](https://search.libraryofleaks.org/)
- [10] [LeakRadar](https://leakradar.io/)
- [11] [OSINT InfoStealers.Info](https://infostealers.info/en/info)
- [12] [Leak-Lookup - Công cụ tìm kiếm sự cố rò rỉ dữ liệu](https://leak-lookup.com/)
- [13] [Leaked.Domains - Tìm kiếm toàn diện](https://leaked.domains/)
- [14] [WhiteIntel - Nền tảng tình báo và giám sát Dark Web](https://whiteintel.io/)
- [15] [vflame6/leaker](https://github.com/vflame6/leaker)
{{#include ../../banners/hacktricks-training.md}}
