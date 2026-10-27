# Các giao thức thanh toán bảo vệ quyền riêng tư

{{#include ../banners/hacktricks-training.md}}

Các hệ thống thanh toán nâng cao có thể che giấu người trả tiền với người bán, che giấu người nhận hoặc số tiền khỏi sổ cái công khai, hoặc ngăn mint liên kết lần rút tiền với lần đổi tiền. Đây là những thuộc tính khác nhau. Không thuộc tính nào xóa được hồ sơ về việc mua tiền, thiết bị, mạng, giao hàng, kế toán, chế tài hoặc endpoint.

[Danh mục kỹ thuật thanh toán ẩn danh](anonymous-payment-techniques.md) cung cấp các mục `Pros`, `Cons`, `Procedure` từng bước và `Detection` được chuẩn hóa cho mỗi nhóm thanh toán. Trang này trình bày chi tiết hơn về các giao thức nâng cao.

{% hint style="danger" %}
Chỉ sử dụng tiền và đối tác hợp pháp. Không sử dụng giao thức bảo vệ quyền riêng tư để né tránh yêu cầu định danh, chế tài, thuế, kiểm tra nguồn tiền hoặc báo cáo giao dịch. Không vận hành dịch vụ exchange, mint hoặc chuyển tiền nếu chưa hiểu rõ các nghĩa vụ về cấp phép, lưu ký, AML và bảo vệ người tiêu dùng.
{% endhint %}

## So sánh các lựa chọn nâng cao

| Giao thức | Che giấu với công chúng/người bán | Bên đáng tin cậy hoặc có khả năng quan sát | Mức độ hoàn thiện/khả dụng |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Bên ngoài không thể liên kết mã thanh toán có thể tái sử dụng với các output dùng một lần | Đồ thị Bitcoin công khai vẫn tồn tại; máy chủ wallet/index có thể thấy các lần quét | Đặc tả hoàn tất; mức hỗ trợ wallet khác nhau |
| Zcash Orchard được shield hoàn toàn | Người gửi, người nhận và số tiền được mã hóa trên chuỗi | Backend/mạng của wallet và các khâu mua/bán ra vẫn có thể thấy | Đã triển khai; mức hỗ trợ shielded khác nhau tùy wallet/exchange |
| GNU Taler | Người bán không cần biết danh tính người trả tiền; thu nhập của người bán vẫn có thể kiểm toán | Taler exchange/ngân hàng thấy nguồn tiền; người bán thấy đơn hàng | Việc triển khai còn giới hạn về địa lý |
| Chaumian e-cash liên bang | Federation không nên liên kết các token đã phát hành với giao dịch nội bộ/lần đổi tiền | Quorum guardian lưu ký khoản dự trữ; gateway thấy hoạt động tại ranh giới | Các triển khai cộng đồng mới xuất hiện |
| Lightning BOLT 12/route blinding | Giảm tiết lộ thông tin về người nhận/node và tuyến đường | Các endpoint, hop được chọn, chuỗi cấp vốn và dịch vụ wallet | Tùy thuộc vào mức hỗ trợ của wallet |
| Thẻ/token ảo | Người bán nhận thông tin xác thực bị giới hạn, không phải PAN có thể tái sử dụng | Issuer/network vẫn lưu thông tin người trả tiền và giao dịch | Phổ biến, đã hoàn thiện |

## Bitcoin Silent Payments (BIP 352)

Silent Payments cho phép người nhận công bố một mã thanh toán tĩnh, trong khi mỗi người gửi tạo ra một output Taproot duy nhất. Người quan sát chuỗi bên ngoài không thể trực tiếp liên kết các output đó với mã đã công bố; cũng không cần yêu cầu địa chỉ tương tác hoặc tạo output thông báo trên chuỗi. BIP 352 được đánh dấu **Complete**, nhưng làm tăng chi phí quét và không tương thích với các wallet chưa triển khai giao thức này.<sup>[[1]](#references)</sup>

### Quy trình của người nhận

1. Chọn wallet đang được duy trì và hỗ trợ rõ ràng việc nhận BIP 352; kiểm tra tính năng trong tài liệu hiện tại của wallet, không dựa vào lời khẳng định trên mạng xã hội.
2. Sao lưu seed wallet và dữ liệu descriptor/khóa Silent Payment theo phương thức khôi phục được tài liệu wallet hướng dẫn. Trước khi công bố mã, hãy thử tìm giao dịch với một khoản nhỏ trên testnet/mainnet.
3. Tạo **label** riêng cho chiến dịch, hóa đơn hoặc đối tác nếu wallet hỗ trợ label BIP 352. Label hỗ trợ kế toán nội bộ mà không công bố địa chỉ có thể liên kết.
4. Công bố mã Silent Payment tĩnh qua một kênh đã xác thực. Mã có thể tái sử dụng, nhưng kẻ giả mạo có thể thay bằng mã của chúng.
5. Khi khả thi, hãy quét bằng full node cục bộ. Máy chủ lập chỉ mục/quét của bên thứ ba có thể biết thời điểm yêu cầu hoặc dữ liệu lọc, dù không thể chi tiêu.
6. Gắn label cho các UTXO đã phát hiện và áp dụng các quy tắc kiểm soát coin như với Bitcoin thông thường. Việc chi tiêu hoặc hợp nhất chúng có thể làm lộ mối liên hệ sở hữu.
7. Xác nhận rằng có thể khôi phục và tìm thấy các khoản thanh toán mà không phụ thuộc vào index bên ngoài chưa được sao lưu.

### Quy trình của người gửi

1. Xác nhận wallet hỗ trợ gửi đến phiên bản địa chỉ đó và xác thực mã tĩnh dài của người nhận.
2. Để wallet tạo output; tuyệt đối không tự chuyển đổi hoặc cắt ngắn mã.
3. Kiểm tra cẩn thận các input được chọn. Silent Payments tăng cường quyền riêng tư của địa chỉ người nhận, nhưng input của người gửi vẫn nằm trên đồ thị công khai.
4. Sử dụng tính năng tăng phí/PSBT được wallet hỗ trợ. BIP 352 yêu cầu tạo lại output nếu input thay đổi; một số chế độ ký không an toàn.
5. Lưu biên nhận hoặc bằng chứng đã mã hóa cần thiết cho tranh chấp/kế toán.

Silent Payments giải quyết vấn đề công bố địa chỉ người nhận lặp lại. Chúng không che giấu số tiền, thời điểm giao dịch, cụm người gửi, lịch sử mua tiền hoặc việc chi tiêu chung về sau.

## Thanh toán Zcash được shield hoàn toàn

Zcash hỗ trợ các pool giá trị transparent và shielded. Giao dịch shielded Orchard sử dụng bằng chứng zero-knowledge để các node xác minh tính hợp lệ trong khi chi tiết giao dịch được mã hóa; Unified Addresses có thể chứa nhiều loại địa chỉ nhận.<sup>[[2]](#references)</sup> Quyền riêng tư phụ thuộc vào đường đi thực tế mà wallet chọn, không phải ký tự đầu tiên của địa chỉ hiển thị.

### Quy trình shielded

1. Chọn wallet đang được duy trì, nêu rõ hành vi **shielded-by-default** và hỗ trợ Orchard hiện tại. Xác minh nguồn tải xuống và sao lưu/thử khôi phục seed.
2. Mua ZEC hợp pháp và ghi lại giá vốn/nguồn tiền. Exchange vẫn biết việc mua và rút tiền.
3. Nhận tiền qua Unified Address được wallet hỗ trợ, sau đó kiểm tra giao dịch đã vào pool shielded hay chưa. Đừng cho rằng tiền tự động được shield nếu chưa xác nhận cách wallet hoạt động.
4. Ưu tiên chuyển **shielded-to-shielded**. Các giao dịch từ transparent sang shielded và từ shielded sang transparent làm lộ giá trị/thời điểm công khai, có thể cho phép đối chiếu số tiền; đặc tả Orchard lưu ý rằng việc chi tiêu đến địa chỉ không phải Orchard sẽ làm lộ giá trị giao dịch.<sup>[[3]](#references)</sup>
5. Tránh các giao dịch khứ hồi có số tiền chính xác dễ nhận biết và việc chuyển ngay qua ranh giới. Đây là biện pháp bảo vệ quyền riêng tư, không phải sự cho phép che giấu quyền sở hữu hoặc nghĩa vụ báo cáo.
6. Sử dụng phương thức bảo vệ quyền riêng tư mạng được wallet hỗ trợ. Mật mã shielded không che giấu IP/thời điểm với máy chủ wallet hoặc các peer.
7. Lưu hồ sơ tuân thủ nội bộ và chỉ sử dụng viewing key cho mục đích kiểm toán/công bố có chủ đích sau khi hiểu rõ phạm vi của khóa.
8. Xác nhận wallet/exchange của người nhận hỗ trợ trước khi gửi; việc buộc phải dùng địa chỉ nhận transparent sẽ làm thay đổi thuộc tính quyền riêng tư.

## GNU Taler: người trả tiền ẩn danh, người bán có trách nhiệm giải trình

GNU Taler là giao thức thanh toán điện tử mở sử dụng tiền tệ truyền thống, chữ ký mù và tích hợp với exchange/ngân hàng được quản lý. Thiết kế của giao thức nhằm giữ kín danh tính khách hàng với người bán, trong khi người bán vẫn có thể được định danh và chịu thuế.<sup>[[4]](#references)</sup> Đây không phải tiền mã hóa; khả năng sử dụng phụ thuộc vào exchange, ngân hàng, wallet và người bán tương thích trong khu vực.

### Quy trình người dùng tại nơi có triển khai

1. Tìm exchange Taler và người bán đang hoạt động, hỗ trợ loại tiền/khu vực liên quan; đọc điều khoản, phí, yêu cầu KYC và thông báo quyền riêng tư hiện hành.
2. Cài wallet chính thức và xác minh nguồn. Bảo vệ dữ liệu sao lưu/khôi phục wallet như tiền mặt vì giá trị trong wallet có thể là tài sản dạng bearer.
3. Rút tiền qua quy trình ngân hàng/exchange được hỗ trợ và cung cấp thông tin trung thực. Tổ chức cấp vốn/exchange có thể biết việc rút tiền, dù chữ ký mù phá vỡ liên kết trực tiếp giữa token và lần rút.
4. Xem hợp đồng của người bán trong wallet: danh tính người bán, mặt hàng/mô tả, số tiền, phí, điều khoản hoàn tiền và giao hàng.
5. Thanh toán và lưu dữ liệu biên nhận cần thiết cho hoàn tiền, bảo hành, kế toán hoặc thuế.
6. Nếu cần ngăn người bán liên kết các giao dịch, đừng tái sử dụng các mã định danh phiên/tài khoản tùy chọn của người bán.
7. Đưa metadata của wallet, mạng và giao hàng vào mô hình đe dọa; mật mã thanh toán của Taler không che giấu địa chỉ giao hàng hoặc endpoint bị xâm nhập.

Người bán và exchange vẫn phải chịu trách nhiệm giải trình; việc vận hành một trong hai thành phần có thể là hoạt động dịch vụ thanh toán chịu quản lý.

## Chaumian e-cash liên bang

Chaumian e-cash sử dụng chữ ký mù để mint ký token mà không thấy token chưa được bỏ mù khi token đó được chi tiêu về sau. Fedimint phân tán việc lưu ký dự trữ và ký giữa một federation guardian; tài liệu của Fedimint cho biết guardian thấy tổng dự trữ/các token đang lưu hành nhưng không nên thấy số dư cá nhân hoặc ai đã trả cho ai bên trong federation.<sup>[[5]](#references)</sup>

Đây là **giá trị bearer được lưu ký**. Một quorum guardian đủ lớn có quyền kiểm soát khoản dự trữ; federation gặp sự cố, guardian không trung thực, lỗi phần mềm hoặc mất trạng thái phía client đều có thể gây mất tiền. Các khoản nạp, rút và gateway Lightning là những sự kiện hiển thị tại ranh giới, có thể được liên kết dựa trên thời điểm/số tiền.

### Quy trình giảm thiểu rủi ro

1. Chỉ sử dụng một khoản nhỏ mà bạn có thể chấp nhận mất. Xem các federation công khai/không rõ danh tính là rủi ro cao hơn so với guardian có trách nhiệm giải trình thực tế.
2. Xác minh lời mời tham gia federation qua kênh đã xác thực và ghi lại danh tính guardian, quorum, khu vực pháp lý, phí, phương án khôi phục và chính sách ngừng hoạt động.
3. Cài wallet tương thích đang được duy trì, xác minh wallet và hiểu rõ phương thức sao lưu trước khi nạp tiền.
4. Nạp Bitcoin có nguồn gốc hợp pháp qua quy trình được tài liệu hướng dẫn. Ghi lại giao dịch peg-in để hạch toán và giả định rằng thời điểm/số tiền được công khai hoặc bị biết tại ranh giới.
5. Bên trong federation, sử dụng yêu cầu thanh toán mới và tránh thêm mã định danh tài khoản/chat/giao hàng có thể khôi phục mối liên kết mà chữ ký mù đã loại bỏ.
6. Với thanh toán Lightning, hãy xem gateway là một bên quan sát bổ sung đối với invoice và thời điểm giao dịch qua ranh giới.
7. Đổi/rút tiền theo chính sách, với giả định rằng số tiền dễ nhận biết và thời điểm ngay lập tức có thể được liên kết với khoản nạp hoặc giao dịch bên ngoài.
8. Lưu riêng hồ sơ thuế/nguồn tiền/ủy quyền; không yêu cầu guardian hoặc gateway khai sai hoạt động.

Không mô tả e-cash liên bang là trustless, tự lưu ký hoặc đảm bảo ẩn danh.

## BOLT 12 offers và route blinding

BOLT 12 offers có thể được tái sử dụng mà không cần công bố địa chỉ trên chuỗi ổn định, đồng thời có thể sử dụng blinded path để người trả tiền không cần biết danh tính/node hoặc đường đi rõ ràng của người nhận. Tính năng này bổ trợ, nhưng không thay thế onion routing hiện có của Lightning.

Trước khi sử dụng:

1. Xác nhận wallet của người gửi và người nhận hỗ trợ các tính năng BOLT 12 hiện hành; đừng suy ra khả năng hỗ trợ chỉ từ nhãn chung “Lightning”.
2. Xác thực offer qua kênh khác và kiểm tra số tiền, đơn vị phát hành/mô tả và quy tắc thanh toán định kỳ.
3. Sử dụng ngữ cảnh invoice/thanh toán mới được tạo từ offer.
4. Hạn chế tối đa alias node, thông tin liên hệ công khai và endpoint mạng ổn định.
5. Giả định rằng người gửi/người nhận, hop đầu/cuối, dịch vụ wallet, đồ thị channel và việc cấp vốn/đóng channel trên chuỗi vẫn tiết lộ một phần mối liên hệ.

## Khả năng kiểm toán mà không công bố dữ liệu

Quyền riêng tư và kiểm toán có thể cùng tồn tại:

- Lưu mã nhãn, hóa đơn, ủy quyền, giá vốn và thông tin liên kết quyền sở hữu ở dạng mã hóa bên ngoài giao thức công khai.
- Tách **view/audit key** khỏi khóa chi tiêu khi giao thức hỗ trợ; trước tiên hãy thử trên một wallet mẫu để biết chính xác dữ liệu bị tiết lộ.
- Chỉ cung cấp cho kiểm toán viên bằng chứng có phạm vi tối thiểu cần thiết, thay vì seed hoặc thông tin xác thực cho phép chi tiêu không giới hạn.
- Ghi lại phiên bản phần mềm, giao thức/pool, ID giao dịch hoặc bằng chứng, mục đích đối tác và nguồn tỷ giá tại thời điểm giao dịch.
- Quy định thời hạn lưu trữ và xóa dữ liệu, thay vì tích lũy một đồ thị danh tính vĩnh viễn không được mã hóa.

## Danh sách kiểm tra lựa chọn

- [ ] Trường dữ liệu được che giấu và bên quan sát được xác định chính xác.
- [ ] Đã xác minh khả năng hỗ trợ của wallet/giao thức tại thời điểm giao dịch.
- [ ] Đã ghi lại các mối liên kết từ việc mua tiền, mạng, node/RPC, đối tác, giao hàng và việc chi tiêu về sau.
- [ ] Đã chấp nhận các rủi ro về lưu ký, khôi phục, thanh khoản, khả năng thanh toán của issuer/federation và hoàn tiền.
- [ ] Hồ sơ định danh, thuế, chế tài, nguồn tiền và hồ sơ tổ chức bắt buộc vẫn chính xác.
- [ ] Đã thử thành công quy trình đầu cuối trên khoản nhỏ, bao gồm khôi phục và bằng chứng kiểm toán.

## References

- [1] [BIP 352 — Thanh toán im lặng](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Địa chỉ hợp nhất](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Giao thức shielded Orchard](https://zips.z.cash/zip-0224)
- [4] [Tài liệu GNU Taler](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Cách hoạt động](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
