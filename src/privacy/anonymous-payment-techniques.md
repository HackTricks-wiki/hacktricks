# Danh mục kỹ thuật thanh toán ẩn danh

{{#include ../banners/hacktricks-training.md}}

Danh mục này bao quát các **nhóm** phương thức thanh toán, từ tiền mặt thông thường đến e-cash chữ ký mù và kỹ thuật làm mờ dấu vết trên public chain. “Ẩn danh” luôn là ẩn danh trước một bên quan sát cụ thể. Merchant, issuer, mint, exchange, blockchain analyst, nhà cung cấp mạng, employer và người quan sát trực tiếp sẽ thấy những thông tin khác nhau.

Các quy trình dưới đây dành cho nguồn tiền hợp pháp, thông tin tài khoản trung thực và hoạt động mua sắm được cấp phép. Những kỹ thuật được dùng với mục đích rửa tiền, né lệnh trừng phạt hoặc gian lận danh tính trong các trường hợp được trích dẫn sẽ được giải thích và phát hiện, nhưng quy trình của chúng chỉ là bài tập điều tra pháp chứng mô phỏng — không phải hướng dẫn thực hiện hành vi phạm pháp.

## Ma trận phạm vi

| Nhóm | Đặc tính riêng tư chính | Bên quan sát/độ tin cậy chính | Cách xử lý |
|---|---|---|---|
| Tiền mặt và phương tiện tương đương tiền mặt | không có bản ghi từ mạng thanh toán từ xa | bên nhận và môi trường vật lý | quy trình hợp pháp |
| Giá trị trả trước/thẻ quà tặng/voucher | tách giao dịch đổi khỏi thẻ chính | người bán, issuer và dịch vụ đổi | quy trình hợp pháp, tùy khu vực pháp lý |
| Thẻ ảo/token hóa | che PAN có thể tái sử dụng hoặc tách biệt merchant | issuer/network/wallet vẫn định danh người trả | quy trình hợp pháp |
| Ứng dụng thanh toán/trung gian | merchant có thể thấy bí danh/trung gian | ứng dụng thu thập danh tính/thiết bị/giao dịch | dùng để đối chiếu |
| Bitcoin hygiene/Silent Payments | bí danh và giảm liên kết với người nhận | đồ thị công khai và ranh giới wallet/network | có thể triển khai |
| PayJoin/CoinJoin | làm suy yếu heuristic về quyền sở hữu/liên kết chung | người tham gia/coordinator/network/đồ thị công khai | có thể triển khai nếu được hỗ trợ; cần rà soát pháp lý |
| Lightning/BOLT 12 | định tuyến off-chain và giảm lộ đường đi đến bên nhận | endpoint, hop, dịch vụ và đồ thị channel | có thể triển khai nếu được hỗ trợ |
| Monero/Zcash/MWEB | bảo mật on-chain ở cấp giao thức | việc mua, endpoint, network và ranh giới vẫn còn lộ | có thể triển khai nếu hợp pháp/được hỗ trợ |
| Ứng dụng ZK trên Ethereum | che giấu một liên kết cụ thể giữa phát biểu/hành động | public input, RPC, relayer và ứng dụng | tùy ứng dụng |
| Cashu/Fedimint/Taler | quyền riêng tư của người trả nhờ chữ ký mù | lưu ký của mint/federation/exchange và các ranh giới | mới nổi/tùy triển khai |
| Stablecoin | thanh toán số thuận tiện | chain minh bạch và quyền đóng băng/kiểm soát của issuer | không phải lựa chọn cơ sở để ẩn danh |
| Swap/bridge/DEX | chuyển giá trị giữa tài sản/chain | cả hai đồ thị, contract và nhà cung cấp | cơ chế pháp chứng; chỉ dùng swap thông thường, hợp pháp |
| Mixer/peel/structuring | tăng độ mơ hồ/công sức phân tích đồ thị | đồ thị vào/ra và hồ sơ dịch vụ | chỉ dùng trong bài tập phát hiện mô phỏng |
| Nominee/mule/OTC/front | chèn người/doanh nghiệp trung gian | bên hỗ trợ, ngân hàng, liên lạc | chỉ phân tích hành vi lạm dụng phạm pháp |
| Địa chỉ thanh toán tái sử dụng/stealth | địa chỉ người nhận mới cho mỗi khoản thanh toán | thông báo công khai/thông báo đến wallet và ranh giới wallet | có thể triển khai nếu được hỗ trợ |
| Sidechain bảo mật/state channel | che số tiền/tài sản hoặc các cập nhật trung gian | peer, bridge/federation và quyết toán vòng đời | tùy giao thức |
| Thanh toán qua nhà mạng/open banking/nền tảng | che thẻ chính khỏi merchant | nhà mạng, ngân hàng/PISP hoặc nền tảng định danh khách hàng | thanh toán thông thường có định danh |
| Tín dụng tương hỗ/quyết toán bù trừ | ít hồ sơ quyết toán bên ngoài hơn | đơn vị vận hành sổ cái riêng có đầy đủ ánh xạ | chỉ dành cho người tham gia đã định danh |

## Tiền mặt

**Cơ chế:** giá trị vật lý vô danh được chuyển giao mà không cần issuer xác thực trực tuyến hoặc sổ cái công khai.

**Ưu điểm:** merchant không cần biết danh tính ngân hàng/thẻ; không có đồ thị giao dịch từ xa; dễ hiểu và giao dịch có tính chung cuộc.

**Nhược điểm:** chỉ giao dịch trực tiếp; nguy cơ trộm cắp/thất lạc; tiền thối/biên lai/số serial hoặc yêu cầu báo cáo; việc rút tiền, camera, nhân chứng và địa điểm vẫn có thể liên kết người trả.

**Quy trình:** (1) xác nhận tiền mặt hợp pháp/được chấp nhận và kiểm tra mọi quy định về hạn mức/báo cáo; (2) rút hoặc nhận tiền hợp pháp và lưu hồ sơ kế toán riêng tư; (3) thanh toán cho merchant thông thường mà không cung cấp thông tin nhận diện khách hàng thân thiết/tài khoản không cần thiết; (4) chỉ yêu cầu biên lai bắt buộc; (5) tránh cung cấp thông tin giao hàng/tài khoản nếu giao dịch không cần; (6) ghi lại mục đích kinh doanh hợp pháp trong nội bộ.

**Phát hiện:** đối chiếu két/biên lai/tồn kho, camera và log ra vào theo chính sách áp dụng; điều tra hành vi hoàn tiền mặt bất thường hoặc các khoản lặp lại ngay dưới ngưỡng kiểm soát, nhưng không mặc định việc dùng tiền mặt thông thường là đáng ngờ.

## Lệnh chuyển tiền, lệnh bưu điện, công cụ thanh toán của ngân hàng và thu tiền khi giao hàng

**Cơ chế:** issuer được quản lý chuyển tiền mặt/tiền trong tài khoản thành công cụ có số serial, thanh toán cho người nhận được nêu tên; COD hoãn thu tiền đến khi giao hàng.

**Ưu điểm:** người nhận có thể không nhận được số tài khoản ngân hàng/thẻ chính của người trả; dùng được khi không thể chuyển tiền mặt từ xa; có biên lai rõ ràng.

**Nhược điểm:** issuer/nhà bán lẻ lưu dữ liệu mua hàng/danh tính theo yêu cầu; theo dõi bằng số serial; địa chỉ người nhận/giao hàng; nguy cơ thất lạc/gian lận và hạn chế theo khu vực; nhìn chung không ẩn danh.

**Quy trình:** (1) kiểm tra quy định của issuer, hạn mức, yêu cầu định danh và việc người nhận có chấp nhận hay không; (2) mua bằng thông tin trung thực và nguồn tiền hợp pháp; (3) điền ngay người thụ hưởng/số tiền; (4) giữ số serial/biên lai; (5) dùng dịch vụ giao hàng có theo dõi phù hợp với giá trị; (6) đối chiếu việc quy đổi/hoàn tiền.

**Phát hiện:** hồ sơ mua/quy đổi của issuer, số serial công cụ, nhà bán lẻ/camera, giao hàng và tài khoản người nhận; đánh dấu việc sửa đổi, số serial trùng lặp và quy đổi nhanh ở những địa điểm không nhất quán về địa lý.

## Thẻ trả trước open-loop

**Cơ chế:** phương tiện lưu trữ giá trị có thương hiệu network xác thực giao dịch từ số dư trả trước thay vì tài khoản tín dụng chính.

**Ưu điểm:** hạn chế mức độ lộ thông tin cho merchant và thiệt hại khi mất; tách merchant khỏi PAN chính; dùng được trực tuyến nếu được chấp nhận.

**Nhược điểm:** có hồ sơ mua/kích hoạt/nạp tiền/đăng ký và thiết bị; KYC và hạn mức tùy quy định; lỗi địa chỉ thanh toán; hạn chế rút tiền mặt/hoàn tiền; “không tên” không có nghĩa là không có hồ sơ của issuer.

**Quy trình:** (1) xác minh thông tin hiện tại về issuer, phí, KYC, khu vực địa lý và hỗ trợ thanh toán trực tuyến/định kỳ; (2) mua qua người bán được ủy quyền bằng nguồn tiền hợp pháp; (3) đăng ký thông tin trung thực theo yêu cầu; (4) dùng cho một mục đích/phạm vi riêng; (5) không chia nhỏ khoản nạp hoặc khai man nơi cư trú; (6) giữ bằng chứng mua hàng/chi phí và đóng/thanh lý theo điều khoản của issuer.

**Phát hiện:** đối chiếu người bán/kích hoạt, nguồn tiền, thiết bị/IP, xác thực của merchant, kiểm tra số dư và quy đổi/hoàn tiền. Mẫu hành vi quan trọng hơn nhãn “thẻ trả trước”.

## Thẻ quà tặng, voucher và tín dụng dịch vụ có thể chuyển nhượng dạng closed-loop

**Cơ chế:** giá trị có số hiệu chỉ được đổi tại một merchant/dịch vụ hoặc hệ sinh thái. Tín dụng viễn thông/game/cửa hàng là các biến thể.

**Ưu điểm:** merchant nhận có thể chỉ thấy mã/số dư; phạm vi ảnh hưởng hạn chế; dễ tặng và tách ngân sách.

**Nhược điểm:** người bán và dịch vụ ghi log mua/kích hoạt/đổi; tài khoản/thiết bị/giao hàng vẫn có thể liên kết; lừa đảo, bán lại giá thấp và giới hạn thời hạn/khu vực; quyền hoàn tiền hạn chế.

**Quy trình:** (1) chỉ mua từ kênh được ủy quyền; (2) ghi lại giá trị mã mà không để lộ mã bí mật; (3) không gắn với tài khoản khách hàng thân thiết có thể định danh nếu không cần thiết; (4) đổi qua tài khoản/ngữ cảnh merchant hợp pháp riêng; (5) giữ biên lai đến khi giao dịch được chấp nhận; (6) không bao giờ mua mã theo yêu cầu “thuế/hỗ trợ/tiền chuộc” không được đề nghị trước.

**Phát hiện:** thời điểm phát hành/đổi mã, sự hội tụ thiết bị/tài khoản, mua hàng loạt/theo ngưỡng, một thiết bị kiểm tra nhiều số dư và đổi nhanh ở địa điểm xa nhau.

## Broker thẻ hoặc mã quà tặng được cấp vốn bằng tiền mã hóa

**Cơ chế:** một bên trung gian nhận tiền mã hóa và cấp thẻ, voucher hoặc mã merchant. Đây là chuyển đổi giữa các kênh thanh toán: merchant thấy giá trị thẻ/quà tặng thông thường, còn broker liên kết khoản nạp on-chain với việc phát hành và giao hàng.

**Ưu điểm:** merchant không nhận wallet cấp vốn; hữu ích khi merchant hợp pháp không chấp nhận crypto; giá trị lưu trữ có giới hạn.

**Nhược điểm:** không ẩn danh trước broker/issuer; có quy định KYC, trừng phạt, exchange và chương trình thẻ; đồ thị nạp tiền công khai; tài khoản/thiết bị/email và việc đổi mã nối lại hai phía; rủi ro lừa đảo/mất khả năng thanh toán.

**Quy trình:** (1) xác minh pháp nhân, issuer thẻ, khu vực được hỗ trợ, KYC, phí và chính sách hoàn tiền; (2) chỉ dùng nguồn tiền hợp pháp có chứng từ; (3) thử mệnh giá nhỏ nhất; (4) xác minh giới hạn network/merchant trước khi mua; (5) giữ cả giao dịch blockchain và biên lai broker để kế toán; (6) không bao giờ dùng broker hứa hẹn gian lận danh tính, né trừng phạt hoặc rút tiền mặt “không thể truy vết”.

**Phát hiện:** đối chiếu địa chỉ nạp của broker, số tiền/thời điểm đặc thù, tài khoản/thiết bị và xác thực thẻ hoặc việc đổi mã quà tặng; hồ sơ issuer và broker nối public chain với merchant.

## Thẻ ảo hoặc thẻ khóa theo merchant

**Cơ chế:** issuer ánh xạ PAN/token được tạo ra với tài khoản thực, thường giới hạn merchant, số tiền hoặc ngày hết hạn.

**Ưu điểm:** tránh để lộ PAN có thể tái sử dụng; tách biệt theo merchant; hạn mức chi tiêu và dễ thu hồi; kiểm soát gian lận hoàn thiện.

**Nhược điểm:** issuer vẫn biết người trả, nguồn tiền, merchant, thiết bị/IP và thời điểm; merchant thấy tài khoản/giao hàng; một số khoản hoàn tiền/thanh toán định kỳ không hoạt động; không ẩn danh.

**Quy trình:** (1) dùng tính năng chính thức của issuer được quản lý; (2) tạo thẻ cho một merchant/mục đích; (3) đặt hạn mức và ngày hết hạn thấp nhất đủ dùng; (4) dùng thông tin thanh toán chính xác nếu được yêu cầu; (5) kiểm tra mô tả giao dịch trên sao kê/cách hoàn tiền; (6) khóa/xóa sau khi quyết toán cuối cùng, đồng thời giữ bằng chứng kiểm toán.

**Phát hiện:** ánh xạ token-với-tài-khoản của issuer, xác thực merchant, thiết bị và giao hàng. Bên phòng thủ dùng tín hiệu tái sử dụng theo merchant, tần suất giao dịch và chiếm đoạt tài khoản.

## Token network của ví di động

**Cơ chế:** token hóa thanh toán EMV thay PAN bằng thông tin xác thực bị giới hạn, thường gắn với thiết bị, merchant hoặc ngữ cảnh thanh toán.<sup>[[1]](#references)</sup>

**Ưu điểm:** merchant không nhận PAN có thể tái sử dụng; mật mã thiết bị/dữ liệu động giảm nguy cơ sao chép; có thể thu hồi mà không cần thay thẻ.

**Nhược điểm:** issuer, token service, nền tảng wallet và network lưu các ánh xạ/giao dịch; tài khoản nền tảng/thiết bị và vị trí có thể định danh người trả.

**Quy trình:** (1) thêm thẻ hợp pháp vào wallet chính thức; (2) bảo vệ tài khoản nền tảng/thiết bị bằng xác thực mạnh; (3) xác minh token thiết bị/số cuối tại thời điểm mua; (4) tắt vị trí/analytics không cần thiết nếu được hỗ trợ; (5) xóa ngay thiết bị/token bị mất; (6) xem lại hồ sơ issuer và wallet.

**Phát hiện:** token requestor/device cryptogram và ánh xạ của issuer, telemetry wallet/tài khoản, thiết bị đầu cuối merchant và bằng chứng vật lý.

## Ứng dụng thanh toán, wallet marketplace và trung gian tập trung

**Cơ chế:** dịch vụ duy trì tài khoản và chuyển tiền nội bộ hoặc qua kênh ngân hàng/thẻ; merchant có thể thấy bí danh trong khi dịch vụ thấy cả hai bên.

**Ưu điểm:** tiện lợi, có cơ chế tranh chấp/hoàn tiền, người nhận không nhất thiết thấy thông tin ngân hàng/thẻ.

**Nhược điểm:** đồ thị tập trung về danh tính/xã hội/giao dịch/thiết bị; đóng băng và yêu cầu pháp lý; đối tác có thể làm lộ hồ sơ; việc sử dụng dữ liệu có thể vượt quá nhu cầu thanh toán.<sup>[[2]](#references)</sup>

**Quy trình:** (1) đọc điều khoản về danh tính, quyền riêng tư, lưu giữ dữ liệu và bảo vệ người mua; (2) giảm tối đa việc đồng bộ hồ sơ/danh bạ tùy chọn; (3) chỉ dùng tài khoản riêng với thông tin trung thực khi điều khoản cho phép; (4) bật MFA/cảnh báo; (5) xác minh người nhận và quyền riêng tư của ghi chú/hồ sơ; (6) xuất hồ sơ và gỡ các liên kết không còn dùng.

**Phát hiện:** tài khoản nhà cung cấp, thiết bị/IP, đồ thị liên hệ, nạp/rút tiền, ghi chú và hồ sơ merchant. Bí danh chỉ là giả danh trước đối tác, không phải ẩn danh trước nền tảng.

## Chuyển khoản ngân hàng, ACH, wire và thanh toán tài khoản tức thời

**Cơ chế:** các tổ chức được quản lý chuyển giá trị giữa tài khoản đã định danh và trao đổi dữ liệu thanh toán bắt buộc.

**Ưu điểm:** nhanh, có trách nhiệm giải trình, có thể đảo ngược trong một số trường hợp, hồ sơ đầy đủ; số tài khoản ảo có thể giảm mức độ lộ thông tin cho merchant.

**Nhược điểm:** ngân hàng/processor biết cả hai bên; có sao kê và nội dung tham chiếu; không ẩn danh; dữ liệu AML/Travel Rule cho giao dịch xuyên biên giới.

**Quy trình:** chỉ sử dụng khi chấp nhận được việc phải chịu trách nhiệm giải trình: xác minh độc lập người thụ hưởng, giảm thông tin tùy chọn trong nội dung chuyển khoản, dùng tài khoản/tham chiếu ảo do ngân hàng cung cấp nếu có, bật cảnh báo, giữ hóa đơn và đối chiếu.

**Phát hiện:** hồ sơ ngân hàng/thanh toán có tính xác định, quyền sở hữu tài khoản/người thụ hưởng, thiết bị/phiên và kiểm soát gian lận. Đây là phương thức đối chiếu cơ sở, không phải kỹ thuật ẩn danh.

## Tách biệt tài khoản và merchant

**Cơ chế:** tách biệt danh tính/tài khoản, email bí danh, thẻ và ngữ cảnh giao hàng hợp pháp giúp ngăn các merchant không liên quan dễ dàng liên kết hoạt động, trong khi issuer/bên kiểm soát vẫn giữ ánh xạ.

**Ưu điểm:** giảm rủi ro rò rỉ dữ liệu và liên kết giữa các merchant; dễ kiểm toán; tương thích với thanh toán được quản lý.

**Nhược điểm:** nhà cung cấp vẫn ánh xạ các phạm vi riêng; điện thoại khôi phục/thiết bị/IP và giao hàng có thể nối lại chúng; chính sách có thể cấm nhiều tài khoản.

**Quy trình:** (1) xác định một mục đích; (2) chỉ tạo bí danh/tài khoản phụ phù hợp điều khoản; (3) dùng token/thẻ riêng theo merchant; (4) tắt đồng bộ liên hệ/quảng cáo cá nhân hóa giữa các tài khoản; (5) giữ sổ theo dõi của bên kiểm soát được mã hóa; (6) ngừng dùng các thông tin nhận dạng sau khi hết nhu cầu hoàn tiền/lưu giữ.

**Phát hiện:** nhà cung cấp liên kết phương thức khôi phục, thiết bị, nguồn tiền và IP; merchant liên kết giao hàng, trình duyệt và hành vi tài khoản. Bên phòng thủ cần phân biệt việc tách biệt hợp pháp với gian lận danh tính giả.

## Mua sắm red-team có kiểm soát

**Cơ chế:** SOC không biết về một giao dịch mua trong khi controller của bài tập giữ ánh xạ pháp nhân, người vận hành và hạ tầng.

**Ưu điểm:** bài tập phát hiện thực tế; không làm lộ thông tin cá nhân; có thể xác định và kiểm toán ngay.

**Nhược điểm:** không ẩn danh trước tổ chức/nhà cung cấp; cần nhiều công tác quản trị; rò rỉ nếu xử lý sai sổ ánh xạ của controller.

**Quy trình:** (1) cấp thẻ/wallet/ngân sách riêng theo engagement cho tổ chức; (2) tách vai trò người mua/người vận hành; (3) ghi lại tài sản, số tiền, dịch vụ, mục đích và ngày dừng; (4) lưu ánh xạ quy thuộc với quyền truy cập giới hạn cho controller; (5) không bao giờ dùng danh tính giả/mule/nguồn tiền bị đánh cắp; (6) công bố/đối chiếu chỉ báo và hoàn tiền khi kết thúc.

**Phát hiện:** controller ánh xạ hóa đơn nhà cung cấp và tài sản; SOC kiểm tra khả năng tự phát hiện qua domain, certificate, hosting và traffic thay vì dữ liệu chủ thẻ.

## Vệ sinh địa chỉ Bitcoin và kiểm soát coin

**Cơ chế:** dùng địa chỉ nhận mới, gắn nhãn cục bộ và chọn UTXO có chủ đích giúp giảm việc tái sử dụng địa chỉ và vô tình gộp các phạm vi riêng trên public ledger.

**Ưu điểm:** được hỗ trợ rộng rãi; tự lưu ký; tránh các liên kết công khai đơn giản nhất.

**Nhược điểm:** mọi giao dịch/số tiền vẫn công khai; heuristic input chung/change, thời điểm và việc gộp sau này có thể liên kết hoạt động; hồ sơ mua/RPC/network vẫn còn.

**Quy trình:** (1) cài đặt/xác minh wallet được duy trì; (2) sao lưu và kiểm tra khôi phục seed; (3) dùng địa chỉ mới cho mỗi hóa đơn; (4) gắn nhãn nguồn/mục đích cục bộ; (5) dùng coin control để tránh gộp các ngữ cảnh; (6) ưu tiên node cục bộ hoặc kết nối có ý thức về quyền riêng tư; (7) xem trước tiền thối/phí và giữ hồ sơ kế toán hợp pháp.<sup>[[3]](#references)</sup>

**Phát hiện:** đồ thị địa chỉ, heuristic input chung/change với mức độ không chắc chắn, số tiền/thời điểm chính xác, giao dịch gộp, khoản nạp dịch vụ, thời điểm phát giao dịch qua node/RPC và hồ sơ off-chain.

## Bitcoin Silent Payments

**Cơ chế:** BIP 352 cho phép người nhận công bố một code tĩnh trong khi người gửi tạo output Taproot duy nhất qua ECDH; người quan sát bên ngoài không thể liên kết trực tiếp các output với code.<sup>[[4]](#references)</sup>

**Ưu điểm:** mã định danh công khai có thể tái sử dụng mà không phải tái sử dụng địa chỉ; không cần yêu cầu địa chỉ tương tác hoặc output thông báo; hòa lẫn vào các output Taproot.

**Nhược điểm:** người nhận phải quét; mức hỗ trợ wallet khác nhau; đồ thị số tiền/người gửi và việc chi tiêu vẫn công khai; máy chủ index có thể quan sát hoạt động quét.

**Quy trình:** (1) chọn wallet BIP 352 hiện hành; (2) sao lưu/kiểm tra khả năng khôi phục descriptor và hoạt động quét; (3) tạo code có gắn nhãn nếu được hỗ trợ; (4) xác thực code đã công bố; (5) người gửi xem xét input và gửi khoản thử nhỏ; (6) người nhận quét, ưu tiên qua node của mình; (7) giữ các UTXO nhận được tách biệt.

**Phát hiện:** theo thiết kế, không thể nhận diện đáng tin cậy chỉ từ output; analyst dùng input người gửi, số tiền/thời điểm, chi tiêu về sau, hồ sơ wallet/network/index và đối tác.

## PayJoin

**Cơ chế:** người trả và người nhận cùng đóng góp input vào một giao dịch thanh toán, phá vỡ giả định rằng mọi input đều thuộc cùng một chủ sở hữu.<sup>[[5]](#references)</sup>

**Ưu điểm:** giao dịch thanh toán thông thường với quyền riêng tư tốt hơn; có lợi cho đồ thị rộng hơn do làm suy yếu heuristic phổ biến; không cần tập hợp các output bằng nhau.

**Nhược điểm:** cần tương tác/hỗ trợ; endpoint người nhận phải khả dụng; số tiền và giao dịch cuối vẫn công khai; có metadata về triển khai và fallback.

**Quy trình:** (1) xác nhận cả hai wallet được duy trì đều hỗ trợ cùng phiên bản PayJoin; (2) xác thực hóa đơn/endpoint; (3) bắt đầu từ payment URI hỗ trợ PayJoin của wallet; (4) kiểm tra số tiền/phí cuối và chỉ ký input dự kiến; (5) tránh tự chỉnh sửa giao dịch; (6) xác minh giao dịch được phát và đã nhận; (7) ghi lại phương án fallback nếu thương lượng thất bại.

**Phát hiện:** blockchain analyst không được áp đặt cụm input chung; endpoint/nhà cung cấp có thể ghi log thương lượng; dùng bằng chứng wallet/network và chi tiêu về sau thay vì chỉ dựa vào hình dạng giao dịch.

## CoinJoin

**Cơ chế:** nhiều người tham gia cùng tạo một giao dịch với nhiều input/output, thường có mệnh giá bằng nhau, làm tăng độ mơ hồ về mối liên hệ input-output.

**Ưu điểm:** tập hợp mơ hồ on-chain lớn hơn; có các thiết kế tự lưu ký; có cấu trúc vòng rõ ràng.

**Nhược điểm:** metadata coordinator/peer/network; phí/thanh khoản; hình dạng giao dịch có thể nhận diện; change dễ bị gắn dấu và việc gộp sau đó làm mất lợi ích; tính sẵn có của dịch vụ/nhà cung cấp tùy pháp lý.

**Quy trình:** (1) xác minh tính khả dụng và tính hợp pháp hiện tại của wallet/coordinator; (2) cài wallet chính thức và sao lưu; (3) chỉ dùng UTXO hợp pháp; (4) hiểu mô hình mệnh giá, phí và coordinator; (5) gắn nhãn/tách riêng change và output đã trộn; (6) không bao giờ gộp chúng với nhau; (7) định tuyến traffic mạng theo cách được hỗ trợ chính thức và giữ hồ sơ kế toán.

**Phát hiện:** nhận diện cấu trúc phối hợp mà không mặc định có hành vi phạm pháp; tính các ánh xạ/tập hợp ẩn danh khả dĩ, sau đó theo dõi change/gộp, ranh giới dịch vụ và hồ sơ network/coordinator.

## Lightning Network

**Cơ chế:** thanh toán HTLC đi qua các channel được định tuyến bằng onion; phần lớn chi tiết thanh toán không được công bố on-chain, trong khi thông tin cấp vốn/đóng channel và channel công khai thì có.

**Ưu điểm:** nhanh, phí thấp; các bên trung gian thường chỉ biết các hop liền kề; chi tiết thanh toán thông thường nằm ngoài chain.

**Nhược điểm:** người gửi/người nhận và hop đầu/cuối biết nhiều hơn; dò tìm, thời điểm, đồ thị channel, thanh khoản/hồ sơ wallet/LSP; wallet lưu ký định danh người dùng.

**Quy trình:** (1) cân nhắc kỹ việc chọn tự lưu ký hay lưu ký; (2) xác minh khả năng khôi phục wallet/seed/channel; (3) dùng invoice cho đúng khoản thanh toán; (4) chỉ dùng channel riêng/tính năng LSP sau khi đọc các đánh đổi; (5) bảo vệ IP node bằng Tor được hỗ trợ khi cần; (6) tránh tái sử dụng invoice có thông tin định danh; (7) lưu hồ sơ kế toán channel và thanh toán.<sup>[[6]](#references)</sup>

**Phát hiện:** log node/LSP/bên lưu ký, đồ thị/dò channel, lỗi/thời điểm thanh toán và cấp vốn/đóng on-chain; không có giao dịch công khai không có nghĩa là không có hồ sơ.

## BOLT 12 offers và route blinding

**Cơ chế:** một offer có thể tái sử dụng tạo invoice mới và có thể quảng bá các đường đi bị làm mờ để người trả không cần biết node/đường đi rõ ràng của người nhận.

**Ưu điểm:** quyền riêng tư của người nhận; endpoint quyên góp/thanh toán có thể tái sử dụng mà không cần invoice tĩnh; tích hợp với định tuyến onion của Lightning.

**Nhược điểm:** mức hỗ trợ wallet khác nhau; endpoint, hop được chọn và nguồn tiền vẫn còn; liên hệ công khai hoặc endpoint network có thể định danh lại người nhận.

**Quy trình:** (1) xác nhận hỗ trợ BOLT 12 tương thích; (2) xác thực offer; (3) yêu cầu invoice mới; (4) xem xét số tiền/issuer/tính định kỳ; (5) thanh toán qua wallet; (6) xác minh việc nhận/hoàn tiền; (7) giảm tối đa alias/liên hệ node và lưu hồ sơ kế toán.<sup>[[7]](#references)</sup>

**Phát hiện:** telemetry wallet/LSP và hop đầu/cuối, tài khoản phân phối offer, đồ thị thời điểm/giá trị và nguồn tiền; route blinding được thiết kế để giới hạn thông tin người trả nhìn thấy.

## Monero

**Cơ chế:** địa chỉ stealth dùng một lần che liên kết người nhận, RingCT che số tiền và ring signature tạo độ mơ hồ cho người gửi.

**Ưu điểm:** quyền riêng tư là mặc định on-chain; bảo mật thông tin người gửi/người nhận/số tiền; hệ sinh thái wallet/node chuyên dụng lâu đời.

**Nhược điểm:** hồ sơ mua/rút tiền và endpoint/network/đối tác; remote node thấy truy vấn/IP; hỗ trợ exchange/cách xử lý pháp lý khác nhau; sai sót vận hành nhỏ vẫn có thể liên kết các phạm vi.

**Quy trình:** (1) mua hợp pháp và giữ bằng chứng cơ sở/nguồn tiền; (2) cài đặt/xác minh wallet chính thức được duy trì; (3) sao lưu/kiểm tra seed; (4) dùng node cục bộ hoặc đường dẫn remote node qua Tor/I2P có tài liệu; (5) dùng subaddress mới cho mỗi người trả/invoice; (6) gắn nhãn ngữ cảnh cục bộ; (7) chỉ cung cấp bằng chứng giao dịch/quyền xem khi có chủ đích.<sup>[[8]](#references)</sup>

**Phát hiện:** tập trung vào hồ sơ exchange/merchant/thiết bị/network và bằng chứng thu giữ wallet; chỉ riêng việc dùng giao thức không đáng ngờ và public chain cố ý tiết lộ ít thông tin hơn.

## Zcash Orchard được shield hoàn toàn

**Cơ chế:** zero-knowledge proof xác thực giao dịch shielded trong khi người gửi, người nhận và số tiền được mã hóa; các pool transparent và việc chuyển đổi giữa pool vẫn công khai.

**Ưu điểm:** bảo mật on-chain mạnh khi đã shield; viewing key hỗ trợ kiểm toán có phạm vi; tính hợp lệ được giao thức thực thi.

**Nhược điểm:** hỗ trợ wallet/exchange và việc chọn pool thực tế khác nhau; tương quan thời điểm/giá trị tại ranh giới transparent; network/RPC và endpoint vẫn còn.

**Quy trình:** (1) chọn wallet Orchard được duy trì và mặc định shield; (2) xác minh/sao lưu; (3) mua ZEC hợp pháp; (4) nhận vào Unified Address được hỗ trợ và xác nhận pool; (5) ưu tiên giao dịch shielded-to-shielded; (6) dùng quyền riêng tư network được hỗ trợ; (7) thử tiết lộ viewing key trên wallet giá trị nhỏ trước khi kiểm toán.<sup>[[9]](#references)</sup>

**Phát hiện:** ranh giới transparent và hồ sơ dịch vụ, metadata wallet/network và viewing key khi được cung cấp hợp pháp; không mặc định mọi khoản thanh toán đến Unified Address đều đã được shield.

## Mimblewimble và Litecoin MWEB

**Cơ chế:** confidential transaction che số tiền và cơ chế gộp kiểu Mimblewimble loại bỏ lịch sử thông thường chứa nhiều địa chỉ; Litecoin triển khai một extension block tùy chọn song song với chain transparent.

**Ưu điểm:** số tiền được bảo mật và tính thay thế được cải thiện trong miền riêng tư; pruning/gộp hiệu quả.

**Nhược điểm:** peg-in/out tùy chọn tại ranh giới có thể công khai và tương quan; hỗ trợ wallet/exchange; khác biệt về mô hình tương tác/địa chỉ; hồ sơ network và mua tài sản.

**Quy trình:** (1) chọn wallet được duy trì có hỗ trợ MWEB rõ ràng; (2) xác minh/sao lưu và thử số tiền nhỏ; (3) mua hợp pháp; (4) peg vào MWEB và xác minh miền số dư; (5) chỉ giao dịch với người nhận tương thích; (6) tránh peg-out ngay lập tức với đặc điểm dễ nhận biết; (7) giữ hồ sơ kiểm toán riêng tư.<sup>[[10]](#references)</sup>

**Phát hiện:** thời điểm/giá trị peg-in/out công khai, dữ liệu exchange/wallet/node và chi tiêu transparent về sau; chi tiết giao dịch nội bộ được cố ý giảm bớt.

## Ứng dụng quyền riêng tư zero-knowledge trên Ethereum

**Cơ chế:** circuit chứng minh một phát biểu — tư cách thành viên, quyền sở hữu note hợp lệ hoặc quyền ủy quyền — mà không tiết lộ bí mật; contract verifier kiểm tra bằng chứng. Tiền nạp, rút, public input, event và gas vẫn có thể làm lộ liên kết.

**Ưu điểm:** tiết lộ có chọn lọc theo lập trình; ứng dụng có anonymity set; quy tắc có thể xác minh mà không tiết lộ mọi dữ liệu.

**Nhược điểm:** lỗi contract/circuit; anonymity set nhỏ; ranh giới công khai; RPC/IP/session/analytics/nguồn gas; rủi ro pháp lý và ứng dụng liên quan lệnh trừng phạt.

**Quy trình:** (1) xác định chính xác bằng chứng che giấu điều gì; (2) dùng ứng dụng được kiểm toán và duy trì nếu hợp pháp; (3) kiểm tra public input/event và quy tắc nạp/rút; (4) tách wallet thực hiện hành động và tài trợ gas theo đúng thiết kế giao thức; (5) dùng đường dẫn RPC/network có chú trọng quyền riêng tư; (6) thử với giá trị nhỏ; (7) giữ hồ sơ tuân thủ.<sup>[[11]](#references)</sup>

**Phát hiện:** event contract, thời điểm/giá trị nạp/rút, relayer/paymaster, RPC/session, storage/analytics của frontend và ranh giới exchange/merchant về sau. Không được tuyên bố ZK proof che các trường được khai báo là công khai.

## Stablecoin

**Cơ chế:** token được chuyển trên public chain; issuer tập trung có thể đóng băng/đưa vào blacklist hoặc quy đổi với tài khoản đã định danh.

**Ưu điểm:** giá ổn định, thanh khoản và được merchant hỗ trợ; quyết toán nhanh; kế toán đơn giản.

**Nhược điểm:** đồ thị địa chỉ/số tiền/contract minh bạch; cần gas; issuer và exchange có thông tin/quyền kiểm soát danh tính; sàng lọc lệnh trừng phạt; nhìn chung không bảo đảm ẩn danh.

**Quy trình:** xem đây là phương thức thanh toán có định danh: chỉ dùng địa chỉ doanh nghiệp mới để tách biệt phạm vi, xác minh contract token/network, thử số tiền nhỏ, bảo vệ wallet, dùng RPC đáng tin cậy/node cục bộ, lưu cơ sở/nguồn tiền và sàng lọc các bên theo yêu cầu.

**Phát hiện:** đồ thị đầy đủ của token event, danh sách/thao tác đóng băng của issuer, mối liên hệ exchange/RPC/thiết bị và nguồn cấp gas.

## Cashu Chaumian e-cash

**Cơ chế:** mint ký mù các bí mật bearer do client tạo, được bảo chứng bằng dự trữ Bitcoin/Lightning của mint; mint có thể ngăn chi tiêu kép mà không liên kết trực tiếp việc phát hành với lần đổi sau đó.

**Ưu điểm:** token bearer không cần tài khoản; chuyển ngang hàng tức thời; mint không thể liên kết trực tiếp lần rút được làm mù với lần chi tiêu; token có thể chuyển dưới dạng dữ liệu/QR.

**Nhược điểm:** lưu ký/khả năng thanh toán/kiểm duyệt của mint; mất/trộm dữ liệu bearer; ranh giới mệnh giá/thời điểm và Lightning; metadata network; hệ sinh thái phần mềm còn non trẻ.<sup>[[12]](#references)</sup>

**Quy trình:** (1) trước tiên dùng mint thử nghiệm chính thức hoặc giá trị nhỏ có thể bỏ; (2) cài wallet được duy trì và kiểm tra giới hạn sao lưu/khôi phục; (3) xác thực mint và xem xét lưu ký/phí; (4) mint số tiền nhỏ; (5) gửi token qua kênh riêng/QR đã xác thực; (6) người nhận đổi token trước khi xem giao dịch là cuối cùng; (7) quy đổi và đối chiếu. Không bao giờ lưu giá trị đáng kể trong mint không đáng tin cậy.

**Phát hiện:** mint thấy network, ranh giới phát hành/quy đổi/Lightning và tập hợp token đã chi tiêu, nhưng blind signature loại bỏ liên kết token trực tiếp; endpoint/tin nhắn và số tiền/thời điểm đặc thù có thể khôi phục mối liên kết.

## Fedimint federated e-cash

**Cơ chế:** một ngưỡng guardian nắm giữ dự trữ và ký mù e-cash; các giao dịch bearer nội bộ được bảo mật trước guardian, trong khi gateway Lightning kết nối với thanh toán bên ngoài.

**Ưu điểm:** phân tán quyền lưu ký; chuyển nội bộ riêng tư; quản trị cộng đồng; không guardian đơn lẻ nào kiểm soát được dự trữ nếu chưa đạt ngưỡng.

**Nhược điểm:** rủi ro quorum guardian/lưu ký/phần mềm; gateway quan sát invoice/thời điểm; ranh giới nạp/rút; độ phức tạp khi khôi phục trạng thái client.

**Quy trình:** (1) xác minh lời mời federation/guardian/quorum/khu vực pháp lý; (2) cài client được duy trì và thử khôi phục; (3) nạp một khoản nhỏ hợp pháp; (4) dùng yêu cầu thanh toán nội bộ mới; (5) xem gateway là bên quan sát Lightning; (6) thử quy đổi; (7) lưu hồ sơ nguồn tiền/thuế ngoài dữ liệu thanh toán công khai.<sup>[[13]](#references)</sup>

**Phát hiện:** federation thấy tổng số phát hành/quy đổi, gateway thấy invoice bên ngoài, Bitcoin/Lightning thể hiện ranh giới và bằng chứng endpoint/liên lạc có thể liên kết các giao dịch nội bộ.

## GNU Taler

**Cơ chế:** e-cash chữ ký mù tích hợp với ngân hàng nhằm ẩn danh người trả trước merchant, trong khi merchant và thu nhập vẫn chịu trách nhiệm giải trình.

**Ưu điểm:** thiết kế bảo vệ quyền riêng tư người trả; dùng tiền tệ thông thường; merchant chịu trách nhiệm/hoàn tiền; không cần token đầu cơ.

**Nhược điểm:** triển khai còn hạn chế; exchange/ngân hàng thấy nguồn tiền; merchant thấy đơn hàng/giao hàng; rủi ro mất khôi phục/vật mang của wallet; operator được quản lý.

**Quy trình:** (1) tìm exchange/merchant hiện hành cho khu vực/tiền tệ; (2) đọc yêu cầu KYC/phí/quyền riêng tư; (3) cài wallet chính thức; (4) rút hợp pháp từ ngân hàng/exchange được hỗ trợ; (5) xem xét hợp đồng merchant; (6) thanh toán và giữ dữ liệu biên lai/hoàn tiền; (7) tránh các mã định danh phiên merchant không cần thiết.<sup>[[14]](#references)</sup>

**Phát hiện:** khoản rút tại ngân hàng/exchange và khoản nạp vào merchant là các ranh giới có thể quy trách nhiệm; đơn hàng/thiết bị/giao hàng và thời điểm có thể tương quan ngay cả khi coin đã được làm mù.

## Cross-chain bridge, atomic swap và DEX

**Cơ chế:** contract/dịch vụ khóa/đốt một tài sản rồi giải phóng/đúc tài sản khác, hoặc các bên đối tác trao đổi theo cơ chế atomic. Việc này phá vỡ góc nhìn của một sổ cái duy nhất, không phá vỡ tính liên tục về mặt kinh tế.

**Ưu điểm:** khả năng tương tác giữa tài sản/network; có thể tránh một bên lưu ký tập trung; phục vụ nhu cầu danh mục đầu tư/thanh khoản thông thường.

**Nhược điểm:** cả hai chain đều công khai; thời điểm/giá trị/phí/thanh khoản và contract có thể tương quan; hồ sơ bridge/relayer/frontend/RPC; rủi ro smart contract/đối tác và quy định.

**Quy trình swap hợp pháp:** (1) xác minh contract/dịch vụ chính thức và tính khả dụng hợp pháp; (2) kiểm tra lưu ký/kiểm toán/phí/slippage; (3) thử giao dịch nhỏ; (4) ghi lại cả hai transaction ID và tỷ giá; (5) bảo vệ quyền approve; (6) đối chiếu tài sản đích và thu hồi quyền approve không cần thiết. Không dùng swap để che giấu nguồn tiền.

**Phát hiện:** event nạp/rút bridge, số tiền đặc thù sau khi trừ phí, thứ tự thời gian, thanh khoản, relayer/RPC/frontend và các khoản nạp dịch vụ về sau.

## Mixer hoặc tumbler tập trung

**Cơ chế:** dịch vụ nhận tiền nạp vào một pool rồi trả lại các đơn vị khác sau đó, nhằm che mờ ánh xạ trực tiếp giữa input và output.

**Ưu điểm:** về lý thuyết có thể làm tăng độ mơ hồ của giao dịch.

**Nhược điểm:** operator có thể trộm cắp/ghi log; phân tích thời điểm/giá trị đầu vào/đầu ra; rủi ro liên quan lệnh trừng phạt/chuyển tiền và phạm pháp; bị thu giữ có thể làm lộ ánh xạ; nguy cơ bị gắn cờ/từ chối.

**Quy trình:** không cung cấp hướng dẫn trộn tiền thực tế. Tái tạo đồ thị an toàn bằng cách mở rộng [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): tạo dữ liệu nạp, output gộp, phí và độ trễ mô phỏng; cung cấp cho analyst ánh xạ không đầy đủ; đo lường heuristic nào hiệu quả; sau đó công bố ground truth.

**Phát hiện:** nhận diện wallet/contract dịch vụ, tập hợp ứng viên đầu vào/đầu ra, số tiền/phí/thời điểm, tái sử dụng địa chỉ nạp, log bị thu giữ/nhà cung cấp và gộp giao dịch về sau. Ghi rõ mức độ quy thuộc chỉ mang tính xác suất.

## Peel chain, fan-out/fan-in và structuring

**Cơ chế:** giao dịch lặp lại tách các khoản thanh toán nhỏ khỏi tiền thối, chia giá trị qua nhiều địa chỉ, tập trung trở lại ở một nơi thu gom, hoặc chia nhỏ khoản tiền để né kiểm tra.

**Ưu điểm:** làm tăng khối lượng công việc của analyst sơ cấp và số lượng địa chỉ.

**Nhược điểm:** mẫu giá trị/tần suất/liên tục giao dịch dễ nhận biết; endpoint hợp nhất và dịch vụ; bản thân hành vi structuring có thể là bất hợp pháp; tốn phí và dễ xảy ra lỗi vận hành.

**Quy trình:** chỉ dùng dữ liệu CSV/testnet mô phỏng: tạo nguồn tiền lớn, các cạnh thanh toán/tiền thối lặp lại, nhiều nhánh song song và một nơi thu gom; thêm ví dụ lành tính giống exchange; tinh chỉnh phát hiện và ghi nhận false positive.

**Phát hiện:** tính liên tục của đồ thị, mẫu tiền thối lặp lại, tần suất, khoản tiền ngay dưới ngưỡng kiểm soát, endpoint dịch vụ chung và hồ sơ off-chain. Hot wallet của exchange có thể giống các mẫu này, nên bắt buộc phải xét ngữ cảnh.<sup>[[15]](#references)</sup>

## Nominee, money mule, broker OTC và công ty bình phong

**Cơ chế:** người/tài khoản/công ty khác nhận, chuyển đổi hoặc chi tiêu tiền, tạo thêm các lớp pháp lý và vận hành giữa người kiểm soát với giao dịch.

**Ưu điểm đối với đối thủ:** tài khoản đứng tên không lập tức tiết lộ người kiểm soát; có thể kết nối tiền mặt, crypto, hàng hóa và nhiều khu vực pháp lý.

**Nhược điểm:** rủi ro gian lận danh tính/rửa tiền; mỗi bên tham gia tạo thêm hồ sơ liên lạc, ngân hàng/công ty/thuế/giao hàng, phí, mâu thuẫn và nhân chứng; việc tái sử dụng bên hỗ trợ tạo ra các hub.

**Quy trình:** không mô phỏng bằng người/tài khoản thật. Tạo đồ thị mô phỏng gồm controller, bên tuyển dụng, mule, OTC, merchant bình phong và bên thụ hưởng; cài các cạnh thiết bị/IP/tin nhắn/ngân hàng; yêu cầu điều tra viên phân biệt chủ tài khoản với người kiểm soát và ghi lại độ tin cậy của bằng chứng.

**Phát hiện:** thiết bị/IP/phương thức khôi phục dùng chung, người thụ hưởng/tần suất bất thường, nhiều người gửi không liên quan, chuyển tiếp ngay lập tức, mâu thuẫn giữa công ty/giám đốc/hóa đơn, liên lạc và giao tiền mặt/hàng hóa.

## NFT, cờ bạc, hàng hóa merchant và vòng hoàn tiền

**Cơ chế:** giá trị được chuyển thành tài sản tự định giá, số dư cá cược, hàng hóa có thể bán lại hoặc khoản hoàn tiền để tạo ra câu chuyện giao dịch khác.

**Ưu điểm đối với đối thủ:** thay đổi hình thức tài sản và thêm trung gian marketplace/merchant.

**Nhược điểm:** đồ thị tự giao dịch/tài khoản/thiết bị của marketplace; hồ sơ cược/chơi và hoàn tiền; bằng chứng giao hàng/bán lại; phí/thua lỗ; trách nhiệm liên quan gian lận/rửa tiền.

**Quy trình:** không hướng dẫn che giấu. Dùng dữ liệu marketplace mô phỏng với giao dịch tự mua bán giữa các wallet liên quan, định giá phi lý, hoạt động chơi tối thiểu, công cụ hoàn tiền không khớp và địa chỉ giao hàng chung; kiểm chứng phát hiện bằng dữ liệu người sưu tầm/khách hàng hợp pháp.

**Phát hiện:** giao dịch tự thân/vòng tròn, quyền sở hữu/nguồn tiền chung, giá ngoại lệ, bán lại/hoàn tiền ngay, hoạt động kinh tế tối thiểu, thiết bị/giao hàng dùng chung và dòng tiền hội tụ trở lại.

## Wallet bearer vật lý hoặc chuyển token offline

**Cơ chế:** thiết bị, giấy/QR, công cụ bearer phần cứng hoặc token e-cash chuyển quyền kiểm soát một bí mật thay vì phát giao dịch thanh toán tại thời điểm bàn giao.

**Ưu điểm:** không có sự kiện network trực tiếp lúc trao đổi; hữu ích khi offline; hình thức lưu giữ tương tự tiền mặt.

**Nhược điểm:** nguy cơ sao chép/trộm cắp/thất lạc và không chắc tính độc quyền; việc quy đổi/phát giao dịch sau đó có thể liên kết; gặp mặt/giao hàng vật lý; nguy cơ giả mạo/can thiệp.

**Quy trình:** (1) chỉ dùng công cụ/giao thức đã được đánh giá; (2) khởi tạo/xác minh tính xác thực riêng tư; (3) chỉ nạp giá trị nhỏ hợp pháp; (4) chuyển trong ngữ cảnh được phép và có ghi chép; (5) người nhận xác minh hoặc sweep ngay theo yêu cầu của giao thức; (6) không bao giờ cho rằng người gửi không giữ lại bản sao; (7) lưu bằng chứng sở hữu/thuế riêng tư.

**Phát hiện:** giao dịch mua/cấp vốn và việc sweep/quy đổi sau đó, bằng chứng serial thiết bị/can thiệp, hồ sơ giao hàng/gặp mặt và endpoint.

## Invoice theo merchant hoặc yêu cầu thanh toán dùng một lần

**Cơ chế:** merchant tạo yêu cầu dùng một lần gồm số tiền, thời hạn và mã tham chiếu đơn hàng. Người trả thanh toán qua kênh được hỗ trợ mà không trực tiếp tiết lộ thông tin xác thực có thể tái sử dụng cho merchant; issuer hoặc processor vẫn có thể định danh cả hai bên.

**Ưu điểm:** hạn chế việc tái sử dụng thông tin xác thực và mã định danh giữa các merchant; số tiền/thời hạn chính xác giảm lỗi; tương thích với kế toán và hoàn tiền thông thường.

**Nhược điểm:** invoice, giao hàng, trình duyệt, processor và issuer vẫn liên kết được đơn hàng; số tiền/thời điểm duy nhất có thể làm tăng khả năng tương quan; link thanh toán độc hại phổ biến.

**Quy trình:** (1) xác thực merchant một cách độc lập; (2) yêu cầu invoice mới có số tiền, tài sản/network và thời hạn chính xác; (3) kiểm tra nơi nhận và quy tắc hoàn tiền; (4) thanh toán từ phạm vi engagement được phê duyệt; (5) xác minh merchant xác nhận đúng invoice; (6) giữ biên lai và mã tham chiếu giao dịch; (7) để yêu cầu hết hạn thay vì tái sử dụng.

**Phát hiện:** merchant và processor liên kết invoice, session và quyết toán; số tiền/thời điểm duy nhất và giao hàng có thể định danh người trả. **Wallet/thiết bị bị thu giữ:** lịch sử invoice để lộ đối tác và mục đích; giảm tối đa nội dung ghi chú không cần thiết, mã hóa thiết bị và lưu sổ kế toán có thẩm quyền trong hệ thống tài chính được kiểm soát.

## Tín dụng dịch vụ trả trước và token năng lực

**Cơ chế:** dịch vụ chuyển khoản thanh toán thông thường thành tín dụng nội bộ có giới hạn hoặc một capability bearer. Việc sử dụng API/tài nguyên về sau có thể không cần cung cấp lại thẻ ban đầu cho mỗi yêu cầu, nhưng dịch vụ thường vẫn ánh xạ được việc cấp tín dụng với lần đổi.

**Ưu điểm:** giới hạn chi tiêu và thiệt hại khi bị xâm phạm; tách nhân viên vận hành hằng ngày khỏi thông tin xác thực cấp vốn; hỗ trợ ngân sách và thu hồi theo dự án.

**Nhược điểm:** thường là giả danh, không phải ẩn danh; cơ sở dữ liệu dịch vụ, IP đổi và mẫu sử dụng riêng có thể liên kết hoạt động; token bearer có thể bị đánh cắp; hoàn tiền có thể cần người trả ban đầu.

**Quy trình:** (1) mua tín dụng qua tài khoản tổ chức; (2) tạo một dự án và ngân sách; (3) cấp token giới hạn theo dịch vụ, số tiền và thời hạn; (4) chỉ lưu token trong secret manager được phê duyệt hoặc luồng workload identity; (5) thử việc từ chối ngoài phạm vi và sau khi hết hạn; (6) theo dõi mức tiêu thụ; (7) thu hồi và đối chiếu giá trị chưa dùng.

**Phát hiện:** nhà cung cấp liên kết tài khoản cấp vốn, dự án, việc phát hành token và hoạt động sử dụng; bên phòng thủ cảnh báo khi địa lý/quy trình thay đổi và khi mức tiêu thụ bất thường. **Node bị thu giữ:** giả định phần capability còn lại có thể bị sử dụng; đặt thời hạn ngắn, số dư thấp, ràng buộc audience và thu hồi ngay phía server.

## Privacy Pass hoặc token ủy quyền được làm mù

**Cơ chế:** issuer tạo token ủy quyền bảo vệ quyền riêng tư để origin xác thực mà không liên kết lần đổi với lần phát hành. Token có thể đại diện cho quyền sử dụng đã trả phí hoặc quyền truy cập giới hạn tần suất, nhưng bản thân nó không phải tiền tệ đa dụng. Kiến trúc tách vai trò client, attester, issuer và origin; đồng thời cảnh báo rằng IP/thời điểm hoặc thông đồng có thể phá vỡ tính không liên kết.<sup>[[18]](#references)</sup>

**Ưu điểm:** lần đổi không liên kết được đối với dịch vụ hỗ trợ; origin không cần cookie tài khoản có thể tái sử dụng; token được lưu trước có thể tách thời điểm phát hành và sử dụng.

**Nhược điểm:** tùy ứng dụng; độ tin cậy issuer/attester và việc chia nhỏ anonymity set; metadata IP và trình duyệt vẫn còn; token bị đánh cắp hoặc thời điểm phát hành riêng biệt có thể tương quan với việc sử dụng.

**Quy trình:** (1) dùng triển khai tuân thủ loại token Privacy Pass liên quan; (2) xác định chính xác token chứng minh quyền gì; (3) tách quản trị issuer và origin khi mô hình đe dọa yêu cầu; (4) giảm metadata challenge; (5) phát một vài token thử nghiệm và đổi mỗi token một lần tại origin do mình sở hữu; (6) so sánh log để tìm mã định danh ổn định không được phép; (7) thử kiểm soát phát lại, hết hạn, thu hồi/lạm dụng.

**Phát hiện:** origin thấy IP/thời điểm đổi và tính hợp lệ token; issuer/attester thấy ngữ cảnh phát hành; analyst kiểm tra thời điểm và các phân vùng metadata mà không mặc định có lỗi mật mã. **Client bị thu giữ:** token bearer chưa dùng có thể vẫn sử dụng được; giới hạn giá trị, thời hạn và audience, không lưu cùng thông tin xác thực cấp vốn.

## Mua sắm ủy quyền của tổ chức hoặc fiscal sponsor

**Cơ chế:** đội mua sắm được ủy quyền, reseller hoặc fiscal sponsor ký hợp đồng và thanh toán, trong khi đội vận hành nhận dịch vụ có giới hạn. Đây là tách biệt vai trò với hồ sơ trung thực, không phải nominee hay danh tính giả.

**Ưu điểm:** vendor không cần nhận danh tính của từng operator hoặc thông tin thanh toán cá nhân; tuân thủ, thuế và hoàn tiền được tập trung; ngân sách và việc thu hồi quyền rõ ràng.

**Nhược điểm:** sponsor biết người thụ hưởng và mục đích; hợp đồng, phê duyệt, giao hàng và tài khoản vẫn tồn tại; thêm thời gian/phí; tách biệt kém nếu cùng một cá nhân quản trị mọi lớp.

**Quy trình:** (1) ghi lại mục đích kinh doanh, người thụ hưởng và thẩm quyền phê duyệt; (2) chọn bên trung gian được tổ chức phê duyệt; (3) ký hợp đồng bằng thông tin trung thực; (4) cấp tài khoản phụ theo phạm vi dự án, không có thông tin thanh toán cá nhân; (5) tách quản trị viên tài chính khỏi operator; (6) đối chiếu hóa đơn và quyền truy cập; (7) chấm dứt dịch vụ và quyền ủy quyền khi kết thúc.

**Phát hiện:** hồ sơ mua sắm, identity provider, vendor và giao hàng liên kết toàn bộ chuỗi. **Thiết bị vận hành bị thu giữ:** chỉ nên để lộ dự án dịch vụ, không để lộ thông tin xác thực tài chính; giữ hóa đơn và danh tính người trả trong hệ thống tài chính, không lưu trên node thực địa.

## Escrow hoặc quyết toán có điều kiện

**Cơ chế:** agent escrow đáng tin cậy hoặc smart contract giữ giá trị đến khi đáp ứng các điều kiện được ghi nhận. Có thể giảm lượng thông tin trực tiếp giữa người trả và người nhận, trong khi escrow và kênh thanh toán nền tảng vẫn giữ mối liên hệ.

**Ưu điểm:** bảo vệ giao dịch khi có tranh chấp/giao hàng; người trả và merchant có thể ít phải để lộ thông tin xác thực có thể tái sử dụng cho nhau; điều kiện giải ngân có thể kiểm toán.

**Nhược điểm:** rủi ro lưu ký/contract của escrow, phí và nghĩa vụ định danh; contract on-chain công khai; dữ liệu đơn hàng/giao hàng/tranh chấp vẫn còn; không ẩn danh trước bên trung gian.

**Quy trình:** (1) xác minh pháp nhân, lưu ký, phí, cơ chế giải quyết tranh chấp và tài sản được hỗ trợ; (2) lập mốc tiến độ và quy trình hoàn tiền chính xác bằng văn bản; (3) cấp vốn từ tài khoản tổ chức được phê duyệt; (4) xác minh độc lập việc nhận hàng và quyền phê duyệt giải ngân; (5) chỉ giải ngân sau khi có bằng chứng; (6) giữ hồ sơ kiểm toán đầy đủ; (7) đóng quyền hoặc quyền approve contract không còn dùng.

**Phát hiện:** tài khoản/sự kiện contract escrow, thời gian cấp vốn và giải ngân, người thụ hưởng và hồ sơ tranh chấp tiết lộ giao dịch. **Thiết bị bị thu giữ:** session token hoặc quyền approve contract có thể cho phép giải ngân; yêu cầu người phê duyệt riêng/MFA và thu hồi session hoạt động khi mất thiết bị.

## Quyết toán tổ chức theo lô hoặc gộp quỹ

**Cơ chế:** nhiều nghĩa vụ được phê duyệt được tổng hợp và quyết toán bằng ít giao dịch ngân hàng/blockchain hơn, với sổ cái nội bộ riêng phân bổ từng phần. Gộp lô có thể giảm chi tiết mua hàng theo từng giao dịch trên public ledger, nhưng coordinator giữ đầy đủ thông tin quy thuộc.

**Ưu điểm:** phí thấp hơn; ít cạnh public graph hơn; che từng dòng giao dịch trước người quan sát công khai khi số tiền được gộp; kế toán nội bộ rõ ràng.

**Nhược điểm:** coordinator là bên quan sát toàn diện và mục tiêu giá trị cao; tổng tiền/thời điểm riêng biệt có thể tương quan; rủi ro lưu ký và đối chiếu; nếu lạm dụng có thể giống structuring.

**Quy trình:** (1) xác định người tham gia và nghĩa vụ hợp pháp trong hệ thống kế toán; (2) đặt lịch gộp định kỳ có lý do kinh doanh thay vì ngưỡng được thiết kế để né kiểm soát; (3) yêu cầu hai bên phê duyệt tổng số; (4) quyết toán cho người nhận đã xác thực; (5) đối chiếu từng dòng nội bộ với lô; (6) ghi nhận hoàn tiền như các khoản điều chỉnh liên kết; (7) bảo vệ quyền truy cập sổ cái và lưu giữ theo chính sách.

**Phát hiện:** sổ cái coordinator, hồ sơ phê duyệt và người thụ hưởng cung cấp ground truth; analyst công khai cần thận trọng khi phân cụm input/output/giá trị/thời điểm. **Thiết bị người trả bị thu giữ:** chỉ nên chứa yêu cầu của chính nó, không chứa khóa ký của pool hoặc sổ người tham gia.

## Paymaster của account abstraction hoặc gas được tài trợ

**Cơ chế:** relayer/bundler gửi thao tác smart account và paymaster trả phí giao dịch, tránh tạo cạnh cấp gas gốc trực tiếp từ wallet người dùng. Cách này cải thiện một đặc tính của đồ thị; thao tác, contract và telemetry dịch vụ vẫn công khai hoặc có thể quan sát.<sup>[[19]](#references)</sup>

**Ưu điểm:** loại bỏ một liên kết cấp gas phổ biến; hỗ trợ tài trợ có phạm vi và giới hạn tần suất; cải thiện khả năng tiếp cận các ứng dụng quyền riêng tư hợp pháp.

**Nhược điểm:** paymaster/bundler/RPC/frontend có thể tương quan yêu cầu; event contract và public input vẫn còn; chính sách tài trợ tạo dấu vân tay của một nhóm; contract/quyền approve độc hại có thể đánh cắp tài sản.

**Quy trình:** (1) dùng smart account và paymaster được kiểm toán, duy trì trên đúng network; (2) kiểm tra trường nào công khai và sponsor ghi log gì; (3) giới hạn tài trợ theo contract, function, số tiền, nonce và thời hạn; (4) thử với giá trị thấp; (5) gửi qua đường dẫn có chú trọng quyền riêng tư theo thiết kế của ứng dụng; (6) xác minh thao tác và bên trả phí on-chain; (7) thu hồi allowance/session key và lưu hồ sơ tuân thủ.

**Phát hiện:** liên kết log UserOperation, EntryPoint, paymaster, bundler/RPC và ứng dụng; thận trọng khi phân cụm chính sách tài trợ giống nhau. **Wallet bị thu giữ:** session key và quyền approve đang chờ có thể vẫn sử dụng được ngay cả khi không có gas; giới hạn chặt và thu hồi theo chính sách khôi phục của account.

## Ủy quyền thanh toán threshold hoặc multisig

**Cơ chế:** chi tiêu cần đạt ngưỡng chữ ký từ nhiều signer độc lập. Cách này không che giao dịch, nhưng cho phép tách quyền thanh toán khỏi laptop, node thực địa hoặc operator đơn lẻ bị thu giữ.

**Ưu điểm:** chống xâm phạm và nội gián mạnh; phê duyệt có trách nhiệm giải trình; không thiết bị thực địa đơn lẻ nào nắm toàn quyền ký; hỗ trợ khôi phục.

**Nhược điểm:** cần phối hợp và đảm bảo tính sẵn sàng; metadata signer/thiết bị/tài khoản có thể tương quan người tham gia; thiết kế sao lưu kém gây mất tài sản; mẫu multisig công khai có thể nhận diện.

**Quy trình:** (1) xác định signer, ngưỡng, hạn mức và khôi phục trước khi cấp vốn; (2) khởi tạo trên phần cứng/tài khoản được hỗ trợ và tách biệt; (3) xác minh độc lập địa chỉ và bản sao lưu; (4) chỉ cấp cho workload thực địa khả năng tạo yêu cầu chưa ký; (5) yêu cầu rà soát ngoài kênh về người nhận, số tiền và mục đích; (6) thử khôi phục và mất một signer với giá trị nhỏ; (7) thay signer sau khi bị xâm phạm.

**Phát hiện:** hệ thống phê duyệt, thiết bị signer và script/contract công khai cung cấp bằng chứng; bên phòng thủ cảnh báo khi chính sách hoặc tập signer thay đổi. **Node bị thu giữ:** nhiều nhất chỉ nên để lộ một session key quyền hạn thấp hoặc yêu cầu chưa ký; không bao giờ lưu chung tài liệu quorum.

## Tiền tệ cộng đồng/sự kiện closed-loop

**Cơ chế:** hợp tác xã, hội nghị hoặc môi trường thử nghiệm riêng phát hành tín dụng chỉ được đổi giữa người tham gia đã đăng ký. Giao dịch nội bộ có thể ít lộ hơn trước mạng thanh toán toàn cầu, trong khi operator kiểm soát việc phát hành và quy đổi.

**Ưu điểm:** phạm vi kinh tế giới hạn; có thể thử nghiệm UX thanh toán offline hoặc bảo vệ quyền riêng tư; giảm lộ thông tin thẻ bên ngoài; có kiểm soát thử nghiệm rõ ràng.

**Nhược điểm:** anonymity set nhỏ; operator và merchant quan sát hoạt động; chấp nhận và quy đổi hạn chế; quy định cấp phép, bảo vệ người tiêu dùng và thuế vẫn có thể áp dụng với giá trị nội bộ.

**Quy trình:** (1) xin rà soát pháp lý/tuân thủ và công bố điều khoản issuer; (2) đăng ký người tham gia thử nghiệm có sự đồng thuận; (3) giới hạn phát hành và cấm lạm dụng như tiền mặt; (4) dùng yêu cầu thanh toán mới và giảm tối đa mã định danh người tham gia công khai; (5) ghi lại dự trữ tổng hợp và biên lai cá nhân riêng tư; (6) thử việc thất lạc/hoàn tiền/quy đổi; (7) đóng sổ cái và hoàn trả giá trị còn lại như đã hứa.

**Phát hiện:** sổ cái issuer, đăng ký tham gia, merchant và hồ sơ quy đổi tái dựng được dòng tiền; cần rà soát các giao dịch vòng tròn bất thường hoặc rút tiền mặt nhanh. **Wallet bị thu giữ:** số dư cục bộ và đối tác có thể bị lộ; giới hạn giá trị, mã hóa trạng thái và hỗ trợ issuer đóng băng/cấp lại có kiểm toán.

## Địa chỉ thanh toán Bitcoin có thể tái sử dụng và chỉ dẫn thanh toán riêng tư

**Cơ chế:** payment code BIP 47 dùng mã định danh công khai có thể tái sử dụng cùng địa chỉ nạp dùng một lần được dẫn xuất qua ECDH; BIP 351 quy định thiết kế chỉ dẫn thanh toán riêng tư mới hơn. Chúng giảm việc tái sử dụng địa chỉ công khai nhưng cho phép người nhận công bố chỉ dẫn thanh toán ổn định. Thông báo, hỗ trợ wallet, nguồn tiền và cách chọn coin về sau vẫn ảnh hưởng đến quyền riêng tư.<sup>[[20]](#references)</sup>

**Ưu điểm:** một chỉ dẫn công khai có thể tạo ra các địa chỉ riêng biệt; người nhận không cần công bố mọi địa chỉ invoice; wallet tương thích có thể theo dõi các khoản thanh toán được dẫn xuất; hữu ích cho nhà tài trợ/khách hàng hợp pháp lặp lại.

**Nhược điểm:** khả năng tương tác giữa wallet khác nhau; giao dịch thông báo hoặc payment code được công bố có thể liên kết ngữ cảnh quan hệ; người gửi, người nhận và public graph vẫn thấy giao dịch; gộp coin hoặc xử lý change bất cẩn làm mất lợi ích.

**Quy trình:** (1) xác nhận cả hai wallet được duy trì hỗ trợ đúng cùng đặc tả/phiên bản; (2) sao lưu và thử khôi phục trên wallet giá trị thấp; (3) xác thực payment code người nhận qua kênh khác; (4) gửi khoản thử hợp pháp nhỏ; (5) xác minh đã dùng địa chỉ dẫn xuất mới; (6) gắn nhãn quan hệ cục bộ và dùng coin control; (7) thử khôi phục và hoàn tiền trước khi phụ thuộc vào tính năng này.

**Phát hiện:** analyst xem xét mẫu thông báo, nguồn tiền/change, gộp về sau và ranh giới dịch vụ; việc công bố public code xác định ngữ cảnh người nhận ngay cả khi địa chỉ nạp khác nhau. **OPSEC chống chịu khi bị thu giữ:** không lưu spend key trên thiết bị thực địa; chỉ hiển thị quan hệ dạng watch-only nếu có thể. **Giám sát:** cảnh báo giao dịch thông báo bất ngờ, địa chỉ dẫn xuất bị tái sử dụng, lỗi gap-limit/khôi phục wallet và việc gộp ngoài kế hoạch.

## EVM stealth address (ERC-5564)

**Cơ chế:** người gửi dẫn xuất tài khoản stealth dùng một lần từ stealth meta-address của người nhận và công bố announcement có ephemeral public key cùng view tag. Người nhận quét announcement bằng viewing key và dẫn xuất spend key tương ứng. Khả năng liên kết người nhận được cải thiện, nhưng người gửi, số tiền/token, gas, announcement và việc chi tiêu về sau vẫn hiển thị.<sup>[[21]](#references)</sup>

**Ưu điểm:** địa chỉ người nhận mới không cần tương tác; meta-address có thể tái sử dụng; tách vai trò xem và chi tiêu; hoạt động trên các tài sản/ứng dụng EVM được hỗ trợ.

**Nhược điểm:** phải quét announcement và xử lý spam; cấp gas cho địa chỉ mới có thể liên kết lại; người gửi biết người nhận; token/số tiền công khai và việc gộp về sau vẫn còn; hỗ trợ triển khai/wallet khác nhau.

**Quy trình:** (1) trước tiên dùng triển khai được kiểm toán và duy trì trên test network; (2) tạo và sao lưu riêng thông tin viewing và spending; (3) xác thực meta-address; (4) gửi khoản thử giá trị thấp và announcement; (5) quét và dẫn xuất stealth account; (6) thử tài trợ gas được hỗ trợ mà không tạo liên kết cấp vốn cá nhân; (7) ghi lại các trường công khai và giữ hồ sơ kế toán hợp pháp.

**Phát hiện:** theo dõi caller của announcement, token/số tiền, thời điểm, nhà tài trợ gas, chi tiêu và việc gộp; view key có thể chứng minh đã nhận mà không cấp quyền chi tiêu. **OPSEC chống chịu khi bị thu giữ:** scanner nối mạng chỉ nên có vai trò xem nếu được hỗ trợ; giữ spend key và recovery key ở nơi khác. **Giám sát:** cảnh báo announcement sai định dạng/spam, truy cập view key, dẫn xuất spend bất ngờ và stealth output bị chuyển đi khi chưa phê duyệt.

## Liquid Confidential Transactions

**Cơ chế:** Liquid mặc định làm mờ số tiền và loại tài sản của output bằng commitment và proof, nhưng vẫn hiển thị đồ thị giao dịch, số input/output, phí và thời gian block. Peg-in/peg-out và ranh giới dịch vụ vẫn có thể liên kết; người dùng có thể tiết lộ có chọn lọc dữ liệu blinding.<sup>[[22]](#references)</sup>

**Ưu điểm:** bảo mật số tiền và loại tài sản theo mặc định; quyết toán sidechain nhanh; kiểm toán có chọn lọc qua blinding key/descriptor; che giá trị nhạy cảm thương mại trước người quan sát công khai.

**Nhược điểm:** cấu trúc đồ thị và thời điểm vẫn lộ; cần tin cậy federation/bridge và exchange; ranh giới peg và output không được làm mờ; hồ sơ wallet/node/network; người nhận và người gửi biết giao dịch của họ.

**Quy trình:** (1) chọn wallet Liquid được duy trì và xác minh mô hình sao lưu; (2) dùng testnet hoặc số tiền hợp pháp nhỏ; (3) nhận vào confidential address và xác minh wallet đánh dấu output là đã làm mờ; (4) gửi giao dịch confidential thử nghiệm; (5) kiểm tra các trường explorer còn công khai; (6) chỉ xuất blinding proof có phạm vi cần cho kiểm toán; (7) ghi lại ranh giới peg/exchange và đối chiếu tiền.

**Phát hiện:** phân tích đồ thị/phí/thời điểm hiển thị, hồ sơ peg và exchange, metadata network và bằng chứng giải mã về sau; không suy đoán số tiền hoặc tài sản bị che. **OPSEC chống chịu khi bị thu giữ:** tách seed chi tiêu, dữ liệu blinding/view và hoạt động watch-only. **Giám sát:** cảnh báo địa chỉ vô tình không được làm mờ, yêu cầu peg không xác định, thay đổi descriptor và xuất blinding key không được phê duyệt.

## Payment channel hoặc state channel tổng quát

**Cơ chế:** các bên khóa tiền, trao đổi cập nhật trạng thái off-chain có chữ ký và chỉ công bố trạng thái mở, đóng hoặc tranh chấp on-chain. Các khoản thanh toán trung gian không được broadcast toàn cầu, nhưng peer và dịch vụ định tuyến/trung gian thấy phần của họ; endpoint phải lưu trạng thái mới nhất có thể thi hành.<sup>[[23]](#references)</sup>

**Ưu điểm:** nhiều tương tác nhanh, phí thấp và riêng tư trước public ledger; ít chi tiết giao dịch toàn cục hơn; số dư channel giới hạn; hữu ích cho dịch vụ đo theo mức sử dụng và đối tác giao dịch lặp lại.

**Nhược điểm:** peer channel biết nhau và có thể lưu các bản cập nhật; việc mở/đóng/số tiền/thời điểm có thể tương quan; có thể cần giám sát trực tuyến trong thời hạn tranh chấp; rủi ro triển khai và thanh khoản; bản thân channel không tạo anonymity set lớn.

**Quy trình:** (1) chọn triển khai được duy trì và kiểm toán, hiểu thời hạn tranh chấp; (2) mở channel thử nghiệm giá trị thấp giữa các bên do mình sở hữu; (3) trao đổi cập nhật trạng thái có chữ ký cùng nonce duy nhất; (4) sao lưu trạng thái mới nhất có thể thi hành; (5) đóng channel theo thỏa thuận; (6) diễn tập từ chối trạng thái cũ trên testnet; (7) lưu hồ sơ kế toán và peer channel.

**Phát hiện:** public chain cho thấy vòng đời/tranh chấp; peer, dịch vụ watch và transport ứng dụng để lộ thời điểm/các bên off-chain. **OPSEC chống chịu khi bị thu giữ:** giới hạn số dư hot và giữ trạng thái có chữ ký mới nhất trong kho mã hóa có thể khôi phục, tách biệt khỏi node thực địa. **Giám sát:** liên tục theo dõi việc công bố trạng thái cũ, thiếu bản sao lưu, thay đổi peer key và thời hạn tranh chấp sắp đến.

## Thanh toán qua nhà mạng di động

**Cơ chế:** dịch vụ trực tuyến tính phí mua hàng vào thuê bao di động hoặc số dư trả trước qua hệ thống thanh toán của nhà mạng. Merchant có thể nhận xác thực từ nhà mạng thay vì thông tin thẻ/ngân hàng, trong khi nhà mạng biết thuê bao/đường dây, ngữ cảnh thiết bị/network, merchant, số tiền và thời điểm.<sup>[[24]](#references)</sup>

**Ưu điểm:** merchant không nhận số thẻ; khả dụng rộng rãi qua điện thoại; dùng được cho hàng hóa số giá trị thấp; nhà mạng có thể giới hạn và đảo giao dịch.

**Nhược điểm:** định danh mạnh qua SIM/tài khoản và thường cả thiết bị; hạn mức thấp và phí cao; hạn chế danh mục merchant; rủi ro chiếm đoạt tài khoản/SIM swap; nhà mạng và aggregator tạo lịch sử giao dịch đầy đủ.

**Quy trình:** (1) xác nhận khả dụng, hạn mức, phí và điều khoản hoàn tiền với tài khoản nhà mạng của tổ chức; (2) chỉ bật trên đường dây tổ chức chuyên dụng nếu có lý do chính đáng; (3) đặt hạn mức chi tiêu thấp nhất đủ dùng; (4) mua món hàng thử nghiệm lành tính; (5) xác minh biên lai merchant và nhà mạng; (6) tắt ủy quyền định kỳ; (7) đối chiếu và tắt tính năng sau đánh giá.

**Phát hiện:** hồ sơ nhà mạng, aggregator và merchant liên kết đường dây, thuê bao, IP/thiết bị và khoản phí; hóa đơn viễn thông doanh nghiệp để lộ giao dịch. **OPSEC chống chịu khi bị thu giữ:** không dùng số cá nhân và yêu cầu MFA tài khoản nhà mạng ngoài thiết bị thực địa. **Giám sát:** bật cảnh báo phí/SIM change tức thời và dừng khi có đăng ký dịch vụ premium, chuyển tiếp hoặc khôi phục tài khoản bất ngờ.

## Khởi tạo thanh toán open banking

**Cơ chế:** với sự đồng ý rõ ràng của người dùng, payment-initiation service provider (PISP) được quản lý yêu cầu ngân hàng giữ tài khoản khởi tạo chuyển khoản. Merchant có thể không nhận thông tin thẻ, nhưng PISP và ngân hàng vẫn lưu hồ sơ được quản lý về người trả, người nhận, sự đồng ý, thiết bị và giao dịch.<sup>[[25]](#references)</sup>

**Ưu điểm:** không có số thẻ tái sử dụng tại bước thanh toán; xác thực ngân hàng mạnh; quyết toán chính xác giữa các tài khoản; API đồng ý/trạng thái; đối chiếu rõ ràng.

**Nhược điểm:** không ẩn danh trước ngân hàng/PISP; người nhận thường thấy thông tin tài khoản pháp lý hoặc nội dung tham chiếu; rủi ro phishing/redirect; biện pháp bảo vệ hoàn tiền khác nhau theo khu vực pháp lý; metadata đồng ý tạo thêm một bên quan sát.

**Quy trình:** (1) xác minh PISP hiện được quản lý và domain callback của merchant là thật; (2) bắt đầu từ yêu cầu của merchant; (3) kiểm tra người nhận, số tiền, nội dung tham chiếu và phạm vi đồng ý yêu cầu tại ngân hàng; (4) chỉ cho phép khoản thanh toán đơn lẻ; (5) xác minh trạng thái cuối một cách độc lập; (6) thu hồi phần đồng ý còn lại nếu có; (7) giữ biên lai và đối chiếu.

**Phát hiện:** log ngân hàng/PISP/merchant và nội dung chuyển khoản cung cấp khả năng quy thuộc mạnh. **OPSEC chống chịu khi bị thu giữ:** không lưu thông tin xác thực và khôi phục ngân hàng trên thiết bị vận hành/thực địa; thiết bị chỉ nên giữ quyền sử dụng dịch vụ đã thanh toán. **Giám sát:** dùng cảnh báo giao dịch/đồng ý của ngân hàng và điều tra quyền PISP mới, người nhận bị thay đổi hoặc callback trạng thái ngoài session dự kiến.

## Wallet nền tảng, số dư cửa hàng ứng dụng hoặc tín dụng trong ứng dụng

**Cơ chế:** nền tảng tính phí người dùng hoặc đổi tín dụng tài khoản, sau đó cấp biên lai có chữ ký hoặc quyền sử dụng cho ứng dụng. Nhà phát triển ứng dụng có thể không nhận được phương tiện cấp vốn ban đầu, trong khi nền tảng ánh xạ tài khoản, thiết bị, nguồn tiền, sản phẩm và việc đổi.<sup>[[26]](#references)</sup>

**Ưu điểm:** merchant/nhà phát triển không nhận PAN chính; có kiểm soát gian lận/hoàn tiền và tài khoản gia đình/doanh nghiệp; số dư trả trước nhỏ có thể giới hạn rủi ro; biên lai có chữ ký đơn giản hóa việc xác minh quyền sử dụng.

**Nhược điểm:** tài khoản nền tảng là trung tâm định danh và hành vi mạnh; thiết bị và khu vực cửa hàng; lịch sử mua/đổi số dư quà tặng; hạn chế rút tiền mặt; kiểm soát gian lận có thể đóng băng tiền; không phải tiền có thể dùng trên nhiều nền tảng.

**Quy trình:** (1) dùng tài khoản nền tảng do tổ chức quản lý nếu chính sách cho phép; (2) xem xét quy tắc về cấp vốn, khu vực, hoàn tiền và giá trị có thể chuyển nhượng; (3) chỉ nạp ngân sách đã phê duyệt; (4) mua sản phẩm lành tính qua cửa hàng chính thức; (5) xác minh ứng dụng chỉ nhận các trường biên lai dự kiến; (6) tắt mua định kỳ; (7) đối chiếu và gỡ tài khoản khỏi phần cứng vận hành.

**Phát hiện:** biên lai/thông báo server của nền tảng, đăng nhập tài khoản/thiết bị và hồ sơ cấp vốn tái dựng được giao dịch mua. **OPSEC chống chịu khi bị thu giữ:** không đăng nhập tài khoản cửa hàng cá nhân trên node thực địa; chỉ cấp quyền sử dụng ứng dụng có phạm vi nếu có thể. **Giám sát:** bật cảnh báo thiết bị/mua mới và điều tra việc phát lại biên lai, thay đổi tài khoản gia đình/tài khoản hoặc sự kiện khôi phục bất ngờ.

## Tín dụng tương hỗ, clearing hoặc quyết toán ròng định kỳ

**Cơ chế:** các bên ghi nhận nghĩa vụ trong sổ cái riêng và chỉ quyết toán vị thế ròng của từng bên theo định kỳ. Sự kiện dịch vụ riêng lẻ không cần tạo thanh toán công khai riêng, nhưng operator sổ cái và các đối tác vẫn giữ dữ liệu quy thuộc chi tiết.

**Ưu điểm:** ít giao dịch bên ngoài và phí hơn; người quan sát công khai chỉ thấy quyết toán ròng; phù hợp với các tổ chức giao dịch lặp lại; hạn mức tín dụng rõ ràng giúp giới hạn rủi ro.

**Nhược điểm:** sổ cái tập trung là bằng chứng đầy đủ và mục tiêu gian lận; rủi ro đối tác/không trả nợ; nghĩa vụ pháp lý/kế toán/thuế; số thành viên nhỏ; khoản chuyển ròng bất thường vẫn có thể tiết lộ mối quan hệ.

**Quy trình:** (1) chỉ dùng giữa các tổ chức đã định danh, đồng ý tham gia và có phê duyệt pháp lý/kế toán; (2) xác định đơn vị, hạn mức tín dụng, chu kỳ quyết toán và quy tắc tranh chấp; (3) ghi lại mọi nghĩa vụ cùng phê duyệt bất biến; (4) để vai trò tài chính riêng tính toán và phê duyệt vị thế ròng; (5) quyết toán qua kênh hợp pháp thông thường; (6) đối chiếu từng dòng với khoản quyết toán; (7) đóng quyền truy cập và lưu hồ sơ theo chính sách.

**Phát hiện:** sổ cái, hóa đơn, phê duyệt và quyết toán ngân hàng/chain cuối cung cấp ground truth; analyst không nên suy luận hoạt động tổng bị thiếu chỉ từ giao dịch ròng. **OPSEC chống chịu khi bị thu giữ:** thiết bị vận hành có thể gửi yêu cầu có giới hạn nhưng không thể sửa số dư hoặc phê duyệt quyết toán. **Giám sát:** cảnh báo vượt hạn mức tín dụng, bút toán ghi lùi ngày, thay đổi quản trị viên, sai lệch đối chiếu và quyết toán đến người thụ hưởng mới.

## Ma trận nguy cơ khi bị thu giữ/xâm phạm

Phần này áp dụng kiểm tra mất/thu giữ cho mọi nhóm. Mục tiêu là giới hạn quyền chi tiêu và việc tiết lộ danh tính không liên quan, đồng thời vẫn giữ kế toán hợp pháp — không phải xóa giao dịch hoặc cản trở điều tra.

| Nhóm kỹ thuật | Wallet/thiết bị/tài khoản bị thu giữ có thể để lộ | Kiểm soát tối thiểu được ủy quyền |
|---|---|---|
| Tiền mặt, lệnh chuyển tiền/COD, giá trị bearer vật lý | biên lai, số serial, ghi chú, giá trị bearer còn lại và liên hệ vật lý | chỉ mang số tiền được phê duyệt; tách kế toán riêng; báo mất ngay; không lập hồ sơ giả |
| Thẻ trả trước, quà tặng, voucher, tín dụng dịch vụ | số dư, issuer, kích hoạt, quy đổi và token tài khoản/session | số dư thấp; một mục đích; đăng ký trung thực; đóng băng/thu hồi qua issuer nếu có |
| Thẻ ảo/token hóa, token wallet, ứng dụng thanh toán | tài khoản issuer, token thiết bị, giao dịch, khôi phục và lịch sử merchant | khóa thiết bị; cảnh báo giao dịch; giới hạn theo merchant; tạm ngưng từ xa qua issuer; không dùng chung tài khoản khôi phục |
| Tách biệt ngân hàng, mua sắm ủy quyền, mua sắm red-team | tổ chức, người phê duyệt, vendor, hóa đơn và dự án | tách vai trò; tài khoản phụ quyền tối thiểu; không lưu thông tin xác thực tài chính trên node vận hành/thực địa |
| Invoice, escrow, quyết toán theo lô | đối tác, mục đích, phê duyệt đang chờ, coordinator hoặc hồ sơ tranh chấp | yêu cầu dùng một lần; người phê duyệt riêng; session giới hạn; sổ cái có thẩm quyền tập trung |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, nhãn, địa chỉ, đồ thị giao dịch và cấu hình network | ký bằng phần cứng/offline; wallet mã hóa; giới hạn passphrase; giao diện watch-only trên thiết bị thực địa; khôi phục có tài liệu |
| Lightning/BOLT 12 | seed, channel, invoice, peer/LSP và cơ sở dữ liệu thanh toán | số dư hot tối thiểu; bản sao lưu mã hóa; danh tính node riêng; đóng/khôi phục theo kế hoạch có tài liệu |
| Monero, Zcash, MWEB, ứng dụng ZK | spend/view key, lịch sử wallet cục bộ, RPC và giao dịch ranh giới | tách vai trò spend/view; dùng phần cứng hỗ trợ khi có; không đăng nhập session exchange trên node thực địa |
| Stablecoin, swap, bridge và DEX | đồ thị minh bạch, quyền approve, trạng thái RPC/frontend và tài sản đích | thu hồi allowance; contract đã xác minh; thử giá trị thấp; đối chiếu đầy đủ |
| Cashu, Fedimint, Taler, Privacy Pass | token bearer, mint/federation/exchange, cache phát hành/quy đổi | số dư nhỏ; sao lưu mã hóa theo khả năng giao thức; quy đổi/cấp lại; không lưu chung thông tin xác thực cấp vốn |
| Paymaster, multisig/threshold | session key, một signer, thao tác đang chờ và chính sách sponsor | session key giới hạn hẹp; quorum độc lập; xoay signer; thiết bị thực địa không thể đạt ngưỡng |
| Mixer/peel/structuring, nominee/front, lạm dụng hoàn tiền/cờ bạc | hồ sơ nhà cung cấp và liên lạc có thể buộc tội, đồ thị và hồ sơ người tham gia | không sử dụng thực tế; chỉ mô phỏng bằng bằng chứng tổng hợp/testnet |
| Tiền tệ cộng đồng/sự kiện | đăng ký, số dư cục bộ, đối tác và quy đổi | giới hạn giá trị; issuer đóng băng/cấp lại; đồng thuận và sổ cái riêng có thể kiểm toán |
| Địa chỉ stealth Bitcoin/EVM có thể tái sử dụng | payment/view/spend key, metadata quan hệ, announcement và output dẫn xuất | vai trò network watch/view-only; vai trò chi tiêu offline/phần cứng; không có session cấp vốn cá nhân |
| Liquid confidential/state channel | seed, dữ liệu blinding/trạng thái mới nhất, peer, ranh giới và tranh chấp | tách bản sao lưu spend/view/state; số dư hot thấp; monitor tranh chấp độc lập |
| Thanh toán qua nhà mạng/open banking/nền tảng | tài khoản điện thoại/ngân hàng/cửa hàng, consent, biên lai, thiết bị và nguồn tiền | tài khoản tổ chức; MFA bên ngoài; hạn mức thấp; không dùng tài khoản cá nhân trên phần cứng thực địa |
| Clearing tín dụng tương hỗ | thành viên, nghĩa vụ, hạn mức, phê duyệt và sổ quyết toán | chỉ gửi yêu cầu vận hành; sổ cái bất biến riêng và hai cấp phê duyệt tài chính |

## Giám sát khả năng bị phát hiện hoặc xâm phạm thanh toán

Việc thanh toán bị từ chối, bị rà soát tuân thủ hoặc wallet ngoại tuyến không chứng minh rằng đang có điều tra. Chỉ giám sát tài khoản, sổ cái và hạ tầng mà tổ chức có quyền quan sát; không bao giờ thăm dò nhà cung cấp hoặc đối tác để kiểm tra xem họ có hợp tác với điều tra viên hay không.

| Kỹ thuật nằm trong phạm vi | Tín hiệu giám sát an toàn | Điều kiện đóng băng/dừng |
|---|---|---|
| Tiền mặt, lệnh chuyển tiền/COD, thẻ trả trước/quà tặng/voucher, giá trị bearer vật lý | sai lệch tồn kho/biên lai, serial trùng, quy đổi/hoàn tiền bất ngờ hoặc báo mất | thiếu công cụ thanh toán, quy đổi ngoài đơn hàng được phê duyệt, biên lai bị sửa hoặc đứt quãng chuỗi lưu giữ |
| Thẻ ảo/token hóa, ứng dụng thanh toán, ngân hàng/ACH/wire, open banking, thanh toán nhà mạng/nền tảng | cảnh báo issuer/ngân hàng/nền tảng, thiết bị/consent/người nhận mới, token tái sử dụng, khôi phục SIM/tài khoản | xác thực lạ, đổi người nhận, phương thức khôi phục mới, SIM swap hoặc phí định kỳ |
| Tách biệt tài khoản/merchant, mua sắm có kiểm soát/ủy quyền, tín dụng dịch vụ | thay đổi IdP/vendor/dự án, vai trò/token/ngân sách, hóa đơn và mức sử dụng | token giữa các dự án, admin lạ, vượt hạn mức, hóa đơn sai lệch hoặc đích không được hỗ trợ |
| Invoice, escrow, quyết toán gộp, tín dụng tương hỗ | thời hạn yêu cầu, phê duyệt/giải ngân, tính toàn vẹn sổ cái, đối chiếu và thay đổi người thụ hưởng | thay đổi số tiền/người nhận, ghi lùi sổ cái, giải ngân đơn phương hoặc lô chưa đối chiếu |
| Địa chỉ Bitcoin/coin control, Silent Payments, BIP47/BIP351 | giao dịch watch-only, trạng thái thông báo/quét, tái sử dụng địa chỉ, nhãn UTXO và gộp | chi tiêu không rõ, output người nhận bị tái sử dụng, lỗi khôi phục/gap của wallet hoặc gộp không được phê duyệt |
| PayJoin/CoinJoin | input/output/phí của đề xuất, tình trạng coordinator, giao dịch cuối | output bị thay thế, phí quá cao, tiết lộ input bất ngờ hoặc chính sách coordinator thay đổi |
| Lightning/BOLT12/channel tổng quát | bản sao lưu channel, sử dụng invoice/offer, thanh khoản, peer/LSP và tranh chấp chain | thanh toán invoice không rõ, peer key thay đổi, đóng channel cũ hoặc sắp hết hạn tranh chấp |
| Monero/Zcash/MWEB/Liquid CT | sự kiện view/watch, loại pool/miền/địa chỉ, descriptor và giao dịch ranh giới | chi tiêu chưa được phê duyệt, hạ cấp sang transparent/không làm mờ, xuất key hoặc ranh giới lạ |
| Ethereum ZK, stealth address, paymaster, stablecoin | contract/announcement, RPC/bundler, nhà tài trợ gas, allowance/session key và hành động của issuer | contract/trường công khai sai, quyền approve/chi tiêu lạ, paymaster thay đổi hoặc issuer đóng băng |
| Cashu/Fedimint/Taler/Privacy Pass | tình trạng mint/federation/exchange, token chi tiêu kép/phát lại, gateway và số dư bearer | quy đổi không rõ, mint key/điều khoản thay đổi, lỗi khôi phục hoặc số dư không nhất quán |
| Swap/bridge/DEX | contract đã xác minh, allowance, xác nhận trên cả hai chain, tỷ giá và tài sản đích | contract/route không khớp, quyền approve không giới hạn, thiếu tài sản đích hoặc sự cố bridge |
| Multisig/threshold | thay đổi tập signer/chính sách, đề xuất đang chờ, quorum và kiểm toán khôi phục | đề xuất/signer không rõ, hạ ngưỡng, kích hoạt khôi phục hoặc bỏ qua chính sách |
| Mixer/peel/structuring, nominee/front, lạm dụng NFT/cờ bạc/hoàn tiền | chỉ ground truth của lab mô phỏng và kết quả phát hiện | có tài khoản, người hoặc giá trị thực đi vào mô phỏng: dừng ngay |

## Quy trình lựa chọn và xác minh

1. Nêu rõ bên nào không được biết trường dữ liệu nào.
2. Xác định issuer/mint/custodian, public ledger, network/RPC, merchant và bên quan sát vật lý.
3. Xác minh khả năng hỗ trợ, tính hợp pháp, hạn mức, lưu ký, khôi phục và hoàn tiền hiện tại.
4. Thử đầu-cuối bằng số tiền hợp pháp nhỏ.
5. Kiểm tra biên lai merchant, sao kê nhà cung cấp, public chain và log wallet/node.
6. Thử sao lưu/khôi phục và tiết lộ có chủ đích cho kiểm toán.
7. Giữ hồ sơ chính xác về nguồn tiền, quyền sở hữu, thuế, lệnh trừng phạt và engagement, đồng thời kiểm soát quyền truy cập.

## References

- [1] [EMVCo — Token hóa thanh toán](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Quan sát về việc các nền tảng thanh toán lớn thu thập dữ liệu](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Bảo vệ quyền riêng tư của bạn](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Đề xuất Payjoin đơn giản](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Giao thức Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Tài liệu Monero — Thông số kỹ thuật và quyền riêng tư mạng](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Giao thức Orchard Shielded](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Xây dựng ứng dụng bảo mật quyền riêng tư bằng zero-knowledge proof](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Giao thức và các giới hạn về quyền riêng tư](https://docs.cashu.space/faq)
- [13] [Fedimint — Cách hoạt động](https://fedimint.org/users/how-it-works)
- [14] [Tài liệu GNU Taler](https://docs.taler.net/)
- [15] [FATF — Chỉ báo rủi ro đối với tài sản ảo](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Quản trị viên, đơn vị trao đổi và người dùng tiền ảo](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [Quy định EU 2023/1113 — Thông tin chuyển tiền và tài sản mã hóa](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Kiến trúc Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction dùng Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Payment Code có thể tái sử dụng](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State channel và payment channel](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Tiêu chuẩn Open Banking — Dịch vụ khởi tạo thanh toán](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
{{#include ../banners/hacktricks-training.md}}
