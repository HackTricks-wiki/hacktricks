# Reconnaissance và các API tình báo mối đe dọa

{{#include ../../banners/hacktricks-training.md}}

Các dịch vụ này hỗ trợ quy trình reconnaissance, đánh giá uy tín, breach hoặc bổ sung dữ liệu. API, hạn mức, giá cả và mục đích sử dụng được phép có thể thay đổi thường xuyên; hãy xác nhận tài liệu hiện hành của nhà cung cấp và phạm vi ủy quyền của engagement trước khi gửi mã định danh khách hàng hoặc dữ liệu nhạy cảm. Để xem trình tự khám phá tài sản, tham khảo [External Recon Methodology](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Kiểm tra xem địa chỉ IP có liên quan đến hoạt động đáng ngờ hoặc độc hại hay không. Có thể cần tài khoản hoặc API key để truy cập.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Kiểm tra xem địa chỉ IP, tên người dùng hoặc địa chỉ email có liên quan đến việc đăng ký tài khoản tự động hoặc hoạt động bot khác đã được báo cáo hay không.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Tìm và xác minh địa chỉ email công việc, cũng như các kiểu thông tin liên hệ liên quan đến domain. Kiểm tra gói hiện tại để biết giới hạn request và mục đích sử dụng được phép.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Tìm kiếm các chỉ dấu tình báo mối đe dọa và hoạt động liên quan đến địa chỉ IP và domain.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Bổ sung dữ liệu doanh nghiệp/hồ sơ có sẵn cho địa chỉ email, domain hoặc công ty. Phạm vi dữ liệu, quyền truy cập và các ràng buộc về quyền riêng tư tùy thuộc vào sản phẩm và gói hiện tại.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Xác định các công nghệ được quan sát trên website và lấy dữ liệu lịch sử hoặc dữ liệu liên kết nếu gói đã chọn cho phép.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Kiểm tra xem địa chỉ IP có liên quan đến hoạt động đáng ngờ hoặc độc hại hay không. Xác nhận các gói API và giới hạn hiện tại.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Tra cứu phân loại và tình báo mối đe dọa của FortiGuard cho domain, URL hoặc địa chỉ IP. Tính khả dụng tùy theo dịch vụ.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Kiểm tra xem địa chỉ IP có bị liệt kê do hoạt động spam đã được báo cáo hay không.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Lấy dữ liệu uy tín của domain dựa trên cộng đồng và các tín hiệu khác của dịch vụ.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Lấy dữ liệu vị trí địa lý, ASN, tổ chức và metadata liên quan của địa chỉ IP. Kiểm tra gói hiện tại để biết hạn mức.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Nền tảng này cung cấp thông tin tình báo DNS và hạ tầng, chẳng hạn như các phân giải lịch sử, domain liên kết với IP hoặc name server, và các bản ghi liên quan. DNS lịch sử có thể tiết lộ địa chỉ origin trước đây, nhưng không thể bypass CDN một cách đáng tin cậy và cần được xác minh.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Bổ sung các thuộc tính nhận dạng và doanh nghiệp hiện có cho địa chỉ email, domain hoặc tên công ty. Xử lý dữ liệu cá nhân theo các yêu cầu về ủy quyền và quyền riêng tư.

## RiskIQ / Microsoft Defender Threat Intelligence (chuyển đổi hệ thống cũ) <sup>[[14]](#references)</sup>

Các tính năng PassiveTotal của RiskIQ đã được chuyển sang Microsoft Defender Threat Intelligence. Quyền truy cập sản phẩm, API và chức năng được duy trì đã thay đổi, vì vậy hãy sử dụng tài liệu hiện hành của Microsoft thay vì dựa vào các giả định về PassiveTotal cũ.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Tìm kiếm domain, địa chỉ IP, địa chỉ email và dữ liệu lịch sử hoặc bị leak được lập chỉ mục, tùy theo cơ chế kiểm soát truy cập của dịch vụ.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Tìm kiếm địa chỉ IP và các chỉ dấu khác để lấy dữ liệu tình báo mối đe dọa và uy tín.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Tìm kiếm địa chỉ IP hoặc dải IP để xem các quan sát về hoạt động quét internet và hoạt động dịch vụ phổ biến. Kiểm tra điều khoản dùng thử và quyền truy cập cộng đồng hiện hành.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Lấy thông tin quét internet và dịch vụ cho địa chỉ IP, host hoặc truy vấn tìm kiếm. Quyền truy cập API phụ thuộc vào gói tài khoản.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Tìm kiếm các bộ dữ liệu về host, chứng chỉ, domain và dịch vụ internet; mô hình dữ liệu và phạm vi bao phủ của nền tảng này khác Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Tìm kiếm trong chỉ mục của nhà cung cấp về các đối tượng và bucket lưu trữ cloud được ghi nhận công khai theo từ khóa.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Tìm kiếm dữ liệu breach được lập chỉ mục theo địa chỉ email, tên người dùng, domain và các bản ghi liên quan. Chỉ sử dụng khi được ủy quyền và tránh để lộ dữ liệu breach không cần thiết.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Tìm kiếm nội dung paste được lập chỉ mục để tìm địa chỉ email hoặc cụm từ khác. Xác minh dịch vụ vẫn còn hoạt động trước khi tích hợp.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Lấy các tín hiệu về uy tín và rủi ro của địa chỉ email.

## GhostProject (dịch vụ lịch sử) <sup>[[24]](#references)</sup>

Trước đây từng quảng bá tính năng tìm kiếm dữ liệu email/mật khẩu bị leak. Hãy xem dịch vụ này là bên thứ ba có rủi ro cao trong việc xử lý dữ liệu và xác minh tính khả dụng, tính hợp pháp cũng như quyền ủy quyền trước khi sử dụng.

## BinaryEdge (đã ngừng hoạt động) <sup>[[25]](#references)</sup>

Từng cung cấp dữ liệu quét internet, mức độ phơi lộ và tình báo mối đe dọa cho địa chỉ IP cùng các tài sản liên quan. Hiện website chuyển hướng đến thông báo chuyển đổi của Coalition và API từ chối request, vì vậy hãy xem dịch vụ này là không khả dụng.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Kiểm tra xem địa chỉ email hoặc domain đã xác minh có xuất hiện trong các vụ breach đã biết hay không. Dịch vụ Pwned Passwords riêng biệt kiểm tra hash mật khẩu bằng tiền tố; dịch vụ này **không** tiết lộ mật khẩu dạng plaintext.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Lấy dữ liệu vị trí địa lý IP, trung tâm dữ liệu, ASN, proxy/VPN và các trường bổ sung liên quan. Hạn mức tùy thuộc vào gói hiện tại.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Bổ sung dữ liệu định hướng IP geolocation và OSINT với một số điểm dữ liệu được chọn. Kiểm tra điều khoản hiện hành về việc sử dụng thương mại.

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
Tra cứu domain (nhà đăng ký, ngày đăng ký và hết hạn, name server, IP hosting và quốc gia) hoặc địa chỉ IP (các domain khác được host trên đó), đồng thời kiểm tra domain hoặc IP có nằm trong danh sách bị xâm phạm miễn phí của dịch vụ hay không: domain phishing và malware bị sinkhole, cùng các địa chỉ đã tấn công cảm biến honeypot của dịch vụ trong 48 giờ qua. Tra cứu trên web và API kiểm tra bị xâm phạm không cần tài khoản; quyền truy cập API để tra cứu yêu cầu gói trả phí.


[DNSDumpster](https://dnsdumpster.com/) cung cấp kết quả DNS reconnaissance.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) cung cấp thông tin tình báo về website, hosting và hạ tầng internet.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) cung cấp giao diện trực tuyến để khám phá subdomain.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [BotScout API](https://botscout.com/api.htm)
- [3] [Hunter API](https://hunter.io/api-documentation)
- [4] [AlienVault OTX API](https://otx.alienvault.com/api)
- [5] [Clearbit](https://dashboard.clearbit.com/)
- [6] [BuiltWith](https://builtwith.com/)
- [7] [FraudGuard](https://fraudguard.io/)
- [8] [FortiGuard Labs](https://www.fortiguard.com/)
- [9] [SpamCop](https://www.spamcop.net/)
- [10] [Web of Trust](https://www.mywot.com/)
- [11] [IPinfo](https://ipinfo.io/)
- [12] [SecurityTrails](https://securitytrails.com/)
- [13] [FullContact](https://www.fullcontact.com/)
- [14] [Microsoft Defender Threat Intelligence](https://learn.microsoft.com/en-us/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti)
- [15] [Intelligence X](https://intelx.io/)
- [16] [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
- [17] [GreyNoise](https://www.greynoise.io/)
- [18] [Shodan](https://www.shodan.io/)
- [19] [Censys](https://censys.com/)
- [20] [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
- [21] [DeHashed](https://www.dehashed.com/)
- [22] [psbdmp](https://psbdmp.ws/)
- [23] [EmailRep](https://emailrep.io/)
- [24] [Nghiên cứu của Cornell — Các giao thức kiểm tra thông tin xác thực bị xâm phạm (bao gồm GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [Tài liệu API NetAPI](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
