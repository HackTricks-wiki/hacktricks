# Thanh toán kỹ thuật số riêng tư

{{#include ../banners/hacktricks-training.md}}

Quyền riêng tư trong thanh toán là việc tiết lộ dữ liệu giao dịch có kiểm soát. Đây không phải là cách hợp pháp hóa tiền bất hợp pháp, trốn thuế hoặc lệnh trừng phạt, né KYC, sử dụng danh tính giả hay che giấu một hoạt động không được ủy quyền. Một khoản thanh toán có thể được giữ kín với người bán nhưng vẫn hoàn toàn hiển thị với đơn vị phát hành, mạng lưới, chủ lao động, cơ quan thuế hoặc điều tra viên.

[Danh mục kỹ thuật thanh toán ẩn danh](anonymous-payment-techniques.md) là danh sách chuẩn hóa, gồm `Pros`, `Cons`, `Procedure` từng bước hợp pháp và `Detection` cho mỗi nhóm. Trang này mở rộng về các phương thức thanh toán thông thường.

{% hint style="danger" %}
Không bao giờ sử dụng tài khoản bị đánh cắp, danh tính tổng hợp, người chuyển tiền hộ, thông tin giả về nơi cư trú hoặc nguồn tiền, chia nhỏ giao dịch (“structuring”) hay môi giới “thẻ không KYC” không minh bạch. Hãy kiểm tra luật hiện hành và điều khoản của nhà cung cấp tại mọi khu vực pháp lý liên quan.
{% endhint %}

## Xác định thuộc tính quyền riêng tư

Hãy xác định bên quan sát trước khi chọn phương thức thanh toán:

| Bên quan sát | Dữ liệu thường thấy | Biện pháp kiểm soát hữu ích | Những gì vẫn còn |
|---|---|---|---|
| Người bán | Tên, email, địa chỉ, token thẻ, IP/thiết bị, giỏ hàng | Thanh toán với tư cách khách, cung cấp tối thiểu dữ liệu tùy chọn, thẻ ảo riêng cho từng người bán | Dữ liệu giao hàng, tài khoản và chống gian lận |
| Đơn vị phát hành/đơn vị xử lý thanh toán | Danh tính pháp lý, nguồn tiền, người bán, số tiền, thời gian, thiết bị | Chọn nhà cung cấp được quản lý với điều khoản quyền riêng tư/bảo mật tốt | Nhà cung cấp vẫn xử lý và có thể lưu giữ/tiết lộ hồ sơ |
| Chủ lao động/chủ sở hữu hoạt động | Chi phí, người thực hiện và mục đích | Ngân sách hoạt động riêng và sổ cái có kiểm soát truy cập | Quản trị hợp pháp đòi hỏi phải quy trách nhiệm nội bộ |
| Người quan sát blockchain công khai | Địa chỉ, luồng giao dịch, số tiền và thời gian, tùy blockchain | Giao thức phù hợp và sử dụng ví đúng cách | Quá trình nhận tiền, điểm cuối và việc chi tiêu về sau có thể liên kết lại hoạt động |
| Nhà cung cấp mạng/RPC/nút | IP, truy vấn ví, phát giao dịch | Nút cục bộ hoặc mạng bảo mật phù hợp | Hành vi về thời gian và điểm cuối vẫn có thể bị đối chiếu |
| Người quan sát trực tiếp | Khuôn mặt, địa điểm, phương tiện, CCTV, hóa đơn | Các biện pháp bảo vệ quyền riêng tư thông thường trong môi trường thực tế | Tiền mặt không khiến một người vô hình ngoài đời |

CFPB cho biết các ứng dụng thanh toán có thể thu thập dữ liệu danh tính, thiết bị, vị trí, danh bạ, giao dịch và hành vi; các quy định về quyền riêng tư của tiểu bang không nhất thiết ngăn việc kiếm tiền từ dữ liệu hoặc mọi hình thức sử dụng thứ cấp.<sup>[[1]](#references)</sup> Hãy đọc thông báo thực tế của nhà cung cấp thay vì suy đoán về quyền riêng tư dựa trên tên sản phẩm.

## So sánh các phương thức thanh toán

| Phương thức | Lợi ích về quyền riêng tư | Các bên quan sát/liên kết chính | Trường hợp sử dụng phù hợp |
|---|---|---|---|
| Tiền mặt | Không có sổ cái của mạng lưới thanh toán | Người nhận, camera, nhân chứng, quy định báo cáo tiền mặt | Mua sắm hợp pháp tại địa phương, nơi chấp nhận tiền mặt |
| Thẻ trả trước/thẻ quà tặng open-loop | Tách số thẻ khỏi thẻ chính | Người bán, nhà cung cấp kích hoạt/đăng ký, nguồn tiền, người bán hàng | Lập ngân sách hoặc tách biệt với phương thức thanh toán chính tại một số người bán |
| Số thẻ ảo/dùng một lần | Che PAN có thể tái sử dụng khỏi người bán; dễ thu hồi | Đơn vị phát hành vẫn biết danh tính và giao dịch | Tách biệt giao dịch trực tuyến theo từng người bán |
| Token của ví di động | Thiết bị/người bán nhận token thay vì PAN gốc | Nhà cung cấp ví, đơn vị phát hành, mạng lưới thanh toán và người bán | Bảo mật thông tin xác thực, không phải ẩn danh |
| Chuyển khoản/ứng dụng ngân hàng | Dễ tạo dấu vết kiểm toán | Ngân hàng/ứng dụng, bên đối tác và danh tính được liên kết | Thanh toán có thể truy trách nhiệm trong tổ chức |
| Tiền mã hóa | Tùy giao thức; tự quản lý ví có thể giảm mức độ lộ thông tin cho bên lưu ký | Sổ cái công khai hoặc giao thức bảo mật, sàn giao dịch, điểm cuối, bên đối tác | Chuyển tiền hợp pháp sau khi phân tích đặc thù giao thức |

## Tiền mặt

Tiền mặt vẫn được xem là quan trọng đối với quyền riêng tư và khả năng tiếp cận tài chính, đồng thời tránh tạo hồ sơ trên mạng lưới thanh toán.<sup>[[2]](#references)</sup> Tiền mặt không giúp tránh CCTV, nhân chứng, dữ liệu vị trí thiết bị, hóa đơn, truy vết số sê-ri trong một số trường hợp đặc biệt hay nghĩa vụ báo cáo theo luật.

### Quy trình hợp pháp

1. Kiểm tra nơi chấp nhận và giới hạn tiền mặt tại địa phương trước khi giao dịch. Giới hạn khác nhau tùy quốc gia và loại bên tham gia, đồng thời thay đổi theo thời gian.
2. Thực hiện giao dịch mua thông thường trong một lần, trung thực. **Không bao giờ chia nhỏ giao dịch** để tránh ngưỡng hoặc báo cáo.
3. Từ chối việc theo dõi khách hàng thân thiết hoặc thu thập dữ liệu tiếp thị không bắt buộc. Cung cấp trung thực dữ liệu cần thiết cho bảo hành, an toàn, giao hàng, thuế hoặc pháp luật.
4. Lưu bằng chứng mua hàng cần thiết và hồ sơ kế toán bắt buộc trong bộ nhớ mã hóa, kèm thời hạn lưu trữ.
5. Với tổ chức, yêu cầu hoàn trả theo quy trình được phê duyệt và ghi lại người thực hiện, sự cho phép, mục đích, số tiền, ngày tháng và hóa đơn.

Tại Hoa Kỳ, một số doanh nghiệp phải nộp Form 8300 khi nhận tiền mặt trên $10,000, bao gồm các giao dịch có liên quan; cố ý tách giao dịch có thể tự nó cấu thành hành vi chia nhỏ giao dịch trái pháp luật.<sup>[[3]](#references)</sup> Các khu vực pháp lý khác có quy định khác nhau—ví dụ, Tây Ban Nha công bố hạn chế thanh toán tiền mặt theo luật riêng.<sup>[[4]](#references)</sup>

## Thẻ trả trước và thẻ quà tặng

“Trả trước” không có nghĩa là ẩn danh. Cửa hàng, đơn vị phát hành, đơn vị quản lý chương trình, ngân hàng cấp vốn và người bán có thể đối chiếu việc mua, kích hoạt, thiết bị, IP, vị trí và chi tiêu. Việc nạp thêm tiền, rút ATM, sử dụng quốc tế, hạn mức cao hơn hoặc bảo vệ khi mất thẻ thường yêu cầu đăng ký.

Hướng dẫn dành cho người tiêu dùng tại Hoa Kỳ giải thích rằng đơn vị phát hành có thể yêu cầu dữ liệu danh tính để xác minh theo luật và có thể từ chối thẻ đã đăng ký nếu việc xác minh thất bại.<sup>[[5]](#references)</sup> Quy định của FinCEN xác định các chương trình trả trước và bên tham gia nào phải thực hiện nghĩa vụ AML.<sup>[[6]](#references)</sup> Tại EU, các ngoại lệ hẹp dành cho tiền điện tử ẩn danh đã bị thu hẹp theo Directive (EU) 2018/843; Regulation (EU) 2024/1624 tiếp tục thay đổi khuôn khổ này nhưng nhìn chung chỉ áp dụng từ **10 July 2027**, vì vậy không nên mô tả quy định này là đã có hiệu lực vào năm 2026.<sup>[[7]](#references)</sup>

Chỉ sử dụng giá trị trả trước khi được nhận hợp pháp từ đơn vị phát hành có thể xác định danh tính, điều khoản của đơn vị cho phép mục đích sử dụng dự kiến, và lợi ích là lập ngân sách hoặc tách biệt khỏi thông tin xác thực thanh toán chính. Tránh thị trường bán lại và môi giới quảng cáo thẻ “không tên” không thể xác minh: giá trị có thể bị đánh cắp, đã được sử dụng, bị giới hạn theo khu vực địa lý hoặc bị tịch thu.

## Thẻ ảo và token của ví

Số thẻ ảo (VCN) thường được phát hành qua một tài khoản thực đã xác minh. Số thẻ riêng cho từng người bán hoặc dùng một lần giúp giảm rủi ro lộ dữ liệu và đối chiếu PAN giữa các người bán; chúng **không** che giấu giao dịch với đơn vị phát hành. Tương tự, token hóa mạng lưới thay thế thông tin xác thực thẻ bằng một token có phạm vi giới hạn.<sup>[[8]](#references)</sup>

### Quy trình tách biệt giao dịch theo người bán

1. Mở tài khoản với đơn vị phát hành được quản lý bằng thông tin danh tính, nơi cư trú và nguồn tiền chính xác.
2. Bảo vệ tài khoản bằng mật khẩu riêng biệt, MFA chống phishing nếu có, cảnh báo đăng nhập và mã khôi phục được lưu ngoại tuyến.
3. Tạo VCN bị khóa theo người bán hoặc chỉ dùng một lần. Đặt giới hạn hợp lý về số tiền/thời gian nếu được hỗ trợ.
4. Thanh toán với tư cách khách và chỉ bỏ qua các trường hồ sơ, khách hàng thân thiết và tiếp thị **không bắt buộc**. Cung cấp thông tin thanh toán, giao hàng và thuế chính xác khi được yêu cầu.
5. Tránh đăng nhập qua các nhà cung cấp danh tính không liên quan; sử dụng trình duyệt riêng cho hoạt động/tài khoản và đường truyền mạng được phê duyệt.
6. Lưu hóa đơn và thông tin đối chiếu VCN với mục đích sử dụng trong sổ cái nội bộ được mã hóa.
7. Khóa hoặc thu hồi số thẻ sau thời hạn hoàn tiền/tranh chấp giao dịch; theo dõi tài khoản chính để phát hiện các khoản ủy quyền bất thường.

Capital One và Google ghi rõ rằng số thẻ ảo vẫn gắn với tài khoản gốc, còn EMVCo/Visa mô tả token hóa là việc thay thế thông tin xác thực và giới hạn phạm vi sử dụng, chứ không phải ẩn danh người thanh toán.<sup>[[8]](#references)</sup>

## Giao hàng, tài khoản và hoàn tiền

Khoản thanh toán chỉ là một mắt xích trong đồ thị liên kết:

- Thẻ riêng biệt sẽ mất tác dụng nếu bạn tái sử dụng email cá nhân, số điện thoại, hồ sơ trình duyệt, địa chỉ IP hoặc tài khoản khách hàng thân thiết.
- Việc giao hàng thực tế thường cần người nhận và địa điểm hợp pháp. Không sử dụng địa chỉ của người không liên quan hoặc giả danh cư dân. Dịch vụ nhận hàng cho doanh nghiệp được phê duyệt an toàn hơn việc bịa thông tin.
- Hàng hóa số có thể ghi lại danh tính tài khoản, IP, dấu vân tay thiết bị, kích hoạt giấy phép và lượt tải xuống.
- Tiền hoàn thường được trả về phương thức thanh toán ban đầu. Yêu cầu nhận tiền rồi chuyển tiếp/hoàn lại sang nơi khác là dấu hiệu cảnh báo gian lận và hành vi sử dụng người chuyển tiền hộ.
- Nội dung mô tả giao dịch của người bán, thông tin trên hóa đơn và thông báo giao hàng có thể để lộ giao dịch nhạy cảm cho người được ủy quyền truy cập tài khoản; hãy chủ động thiết lập quyền truy cập và cảnh báo.

## Giao dịch mua hàng cho red-team được ủy quyền

Một hoạt động cần kín đáo với bên ngoài nhưng phải có thể truy trách nhiệm nội bộ:

1. Có phạm vi công việc, mục đích, mức chi tiêu tối đa, người phê duyệt, người bán/tài sản được phép và quy định hoàn trả bằng văn bản.
2. Sử dụng tài khoản thanh toán do tổ chức kiểm soát và VCN hoặc tài khoản phụ riêng cho từng hoạt động hoặc người bán.
3. Cung cấp thông tin thanh toán và đăng ký chính xác cho nhà cung cấp. Quyền riêng tư trong đăng ký công khai có thể giảm mức độ lộ thông tin nhưng không cho phép khai báo gian dối.
4. Duy trì sổ cái được mã hóa, ghi lại người thực hiện, phê duyệt, mục đích, ngày tháng, số tiền, bên đối tác, mã định danh tài sản và hóa đơn.
5. Sàng lọc bên đối tác theo yêu cầu và tuân thủ nghĩa vụ của nhà cung cấp, lệnh trừng phạt, thuế và báo cáo.
6. Chỉ cấp cho bộ phận tài chính quyền truy cập cần thiết; chỉ cấp cho người thực hiện năng lực chi tiêu giới hạn mà họ cần.
7. Khi kết thúc hoạt động, đóng hoặc khóa thông tin xác thực thanh toán, đối chiếu các khoản phí/hoàn tiền đang chờ và lưu hồ sơ theo chính sách.

Để tìm hiểu lựa chọn riêng tư dành cho tiền mã hóa, xem tiếp [Quyền riêng tư của tiền mã hóa](cryptocurrency-privacy.md). Để tìm hiểu về hạ tầng mà các giao dịch mua này hỗ trợ, xem [Hạ tầng red-team được ủy quyền](authorized-red-team-infrastructure.md).

## Danh sách kiểm tra xác minh

- [ ] Đã ghi lại thuộc tính quyền riêng tư mong muốn và các bên quan sát.
- [ ] Đã kiểm tra gần đây các quy định của nhà cung cấp, người bán và khu vực pháp lý.
- [ ] Thông tin danh tính và nguồn tiền được khai báo trung thực.
- [ ] Đã giảm thiểu dữ liệu tùy chọn của người bán mà không cản trở việc xác minh bắt buộc.
- [ ] Đã hiểu các liên kết giữa nguồn tiền, thiết bị, mạng, tài khoản, giao hàng và hoàn tiền.
- [ ] Không có hành vi né ngưỡng, giao dịch với bên bị cấm, sử dụng người chuyển tiền hộ, thông tin xác thực bị đánh cắp hoặc danh tính của bên thứ ba.
- [ ] Hóa đơn, phê duyệt, hồ sơ thuế và thông tin khôi phục bắt buộc được mã hóa và kiểm soát truy cập.

## References

- [1] [US CFPB — Yêu cầu cung cấp thông tin về việc thu thập, sử dụng và kiếm tiền từ dữ liệu thanh toán của người tiêu dùng và dữ liệu tài chính cá nhân khác](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Nghiên cứu về thái độ thanh toán của người tiêu dùng trong khu vực đồng euro (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Hướng dẫn dành cho Form 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Báo cáo các khoản thanh toán bằng tiền mặt](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Tại sao tôi được yêu cầu cung cấp thông tin cá nhân để kích hoạt hoặc đăng ký thẻ trả trước?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) và [Tôi có thể bị từ chối cấp thẻ trả trước không?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Quy định cuối cùng về quyền truy cập trả trước](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Sử dụng thẻ tín dụng ảo](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
