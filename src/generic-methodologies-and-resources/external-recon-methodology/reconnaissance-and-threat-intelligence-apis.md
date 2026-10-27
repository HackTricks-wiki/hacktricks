# Trinh sát và API tình báo mối đe dọa

{{#include ../../banners/hacktricks-training.md}}

Các dịch vụ này hỗ trợ quy trình trinh sát, đánh giá uy tín, rò rỉ dữ liệu hoặc làm giàu dữ liệu. API, hạn mức, giá cả và mục đích sử dụng được phép của các dịch vụ thường xuyên thay đổi; hãy xác nhận tài liệu hiện hành của nhà cung cấp và phạm vi ủy quyền của hoạt động trước khi gửi mã định danh khách hàng hoặc dữ liệu nhạy cảm. Để xem trình tự khám phá tài sản, hãy tham khảo [Phương pháp trinh sát bên ngoài](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Tra cứu xem một địa chỉ IP có liên quan đến hoạt động đáng ngờ hoặc độc hại hay không. Có thể cần tài khoản hoặc API key để truy cập.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Kiểm tra xem địa chỉ IP, tên người dùng hoặc địa chỉ email có liên quan đến việc đăng ký tài khoản tự động hay hoạt động bot khác đã được báo cáo hay không.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Tìm và xác minh địa chỉ email công việc cũng như các mẫu liên hệ liên quan đến tên miền. Kiểm tra gói hiện tại để biết giới hạn yêu cầu và mục đích sử dụng được phép.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Tìm kiếm các chỉ báo tình báo mối đe dọa và hoạt động liên quan đến địa chỉ IP và tên miền.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Làm giàu địa chỉ email, tên miền hoặc công ty bằng dữ liệu doanh nghiệp/hồ sơ hiện có. Phạm vi dữ liệu, quyền truy cập và các giới hạn về quyền riêng tư phụ thuộc vào sản phẩm và gói hiện tại.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Nhận diện các công nghệ được quan sát trên website và lấy dữ liệu lịch sử hoặc dữ liệu về mối liên hệ nếu gói đã chọn cho phép.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Kiểm tra xem địa chỉ IP có liên quan đến hoạt động đáng ngờ hoặc độc hại hay không. Xác nhận các gói API và giới hạn hiện tại.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Tra cứu phân loại và tình báo mối đe dọa của FortiGuard đối với tên miền, URL hoặc địa chỉ IP. Tính khả dụng khác nhau tùy dịch vụ.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Kiểm tra xem địa chỉ IP có bị liệt kê do hoạt động spam được báo cáo hay không.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Lấy thông tin uy tín của tên miền dựa trên cộng đồng của dịch vụ và các tín hiệu khác.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Lấy dữ liệu định vị địa lý, ASN, tổ chức và siêu dữ liệu liên quan của một địa chỉ IP. Kiểm tra gói hiện tại để biết hạn mức.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Nền tảng này cung cấp thông tin tình báo DNS và hạ tầng như các kết quả phân giải lịch sử, tên miền liên kết với IP hoặc name server và các bản ghi liên quan. DNS lịch sử có thể tiết lộ địa chỉ origin trước đây, nhưng không thể vượt CDN một cách đáng tin cậy và cần được xác thực.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Làm giàu địa chỉ email, tên miền hoặc tên công ty bằng các thuộc tính nhận dạng và doanh nghiệp hiện có. Xử lý dữ liệu cá nhân theo yêu cầu về ủy quyền và quyền riêng tư.

## RiskIQ / Microsoft Defender Threat Intelligence (chuyển đổi từ dịch vụ cũ) <sup>[[14]](#references)</sup>

Các chức năng PassiveTotal của RiskIQ đã được chuyển sang Microsoft Defender Threat Intelligence. Quyền truy cập sản phẩm, API và chức năng được duy trì đã thay đổi; hãy sử dụng tài liệu hiện hành của Microsoft thay vì dựa vào các giả định cũ về PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Tìm kiếm tên miền, địa chỉ IP, địa chỉ email và dữ liệu lịch sử hoặc dữ liệu leak đã được lập chỉ mục, tuân theo các biện pháp kiểm soát truy cập của dịch vụ.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Tìm kiếm địa chỉ IP và các chỉ báo khác để lấy dữ liệu tình báo mối đe dọa và uy tín.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Tìm kiếm địa chỉ IP hoặc dải IP để xem các quan sát về hoạt động quét internet và hoạt động dịch vụ phổ biến. Kiểm tra các điều khoản dùng thử và quyền truy cập cộng đồng hiện hành.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Lấy thông tin quét internet và dịch vụ cho địa chỉ IP, host hoặc truy vấn tìm kiếm. Quyền truy cập API phụ thuộc vào gói tài khoản.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Tìm kiếm các tập dữ liệu về host, certificate, tên miền và dịch vụ internet; mô hình dữ liệu và phạm vi bao phủ khác với Shodan.

## [Tìm kiếm bucket GrayHatWarfare](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Tìm kiếm trong chỉ mục của nhà cung cấp về các đối tượng và bucket lưu trữ đám mây được quan sát công khai bằng từ khóa.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Tìm kiếm trong dữ liệu breach đã lập chỉ mục theo địa chỉ email, tên người dùng, tên miền và bản ghi liên quan. Chỉ sử dụng khi được ủy quyền và tránh để lộ dữ liệu breach không cần thiết.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Tìm kiếm nội dung paste đã lập chỉ mục để tìm địa chỉ email hoặc cụm từ khác. Xác minh dịch vụ vẫn khả dụng trước khi tích hợp.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Lấy các tín hiệu uy tín và rủi ro của một địa chỉ email.

## GhostProject (trước đây) <sup>[[24]](#references)</sup>

Trước đây, dịch vụ này quảng cáo khả năng tìm kiếm dữ liệu email/mật khẩu bị leak. Hãy xem đây là dịch vụ bên thứ ba có rủi ro cao trong việc xử lý dữ liệu và xác minh tính khả dụng, tính hợp pháp cũng như quyền được phép sử dụng trước khi dùng.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Lấy dữ liệu quét internet, mức độ lộ diện và tình báo mối đe dọa cho địa chỉ IP và các tài sản liên quan.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Kiểm tra xem địa chỉ email hoặc tên miền đã xác minh có xuất hiện trong các vụ breach đã biết hay không. Dịch vụ Pwned Passwords riêng biệt kiểm tra hash mật khẩu bằng tiền tố; dịch vụ này **không** tiết lộ mật khẩu dạng văn bản thuần.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Lấy dữ liệu định vị IP, trung tâm dữ liệu, ASN, proxy/VPN và các trường làm giàu liên quan. Hạn mức phụ thuộc vào gói hiện tại.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Làm giàu dữ liệu định vị IP và OSINT với một số điểm dữ liệu được chọn. Kiểm tra điều khoản hiện tại về mục đích sử dụng thương mại.


[DNSDumpster](https://dnsdumpster.com/) cung cấp kết quả trinh sát DNS.<sup>[[29]](#references)</sup>

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
- [31] [Trình tìm subdomain NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
