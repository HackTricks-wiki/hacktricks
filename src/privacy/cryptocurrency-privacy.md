# Quyền riêng tư của tiền mã hóa

{{#include ../banners/hacktricks-training.md}}

Quyền riêng tư của tiền mã hóa là vấn đề về giao thức và vận hành, không đồng nghĩa với bí mật hay miễn nhiễm. Sổ cái công khai, sàn giao dịch, máy chủ ví, các peer mạng, người bán và những giao dịch về sau có thể làm lộ các phần khác nhau của đồ thị giao dịch.

Bắt đầu với [Danh mục kỹ thuật thanh toán ẩn danh](anonymous-payment-techniques.md) để xem định dạng ưu/nhược điểm/quy trình/phát hiện cho từng kỹ thuật. Trang này đi sâu hơn vào cơ chế riêng của tiền mã hóa và các giới hạn trong vận hành.

{% hint style="danger" %}
Chương này dành cho việc tự lưu ký hợp pháp và giảm thiểu dữ liệu. Không sử dụng nội dung này để rửa tiền thu được, né tránh lệnh trừng phạt/thuế/nghĩa vụ báo cáo, giao dịch với các bên bị cấm, đánh lừa nhà cung cấp chịu sự quản lý hoặc vận hành dịch vụ chuyển tiền không có giấy phép. Công nghệ bảo vệ quyền riêng tư không thay đổi nguồn gốc hợp pháp hay quyền sở hữu của tiền.
{% endhint %}

## Mô hình đe dọa theo từng lớp

| Lớp | Bên quan sát | Thông tin thường bị tiết lộ |
|---|---|---|
| Mua vào/rút tiền | Sàn giao dịch, ngân hàng, môi giới, đối tác P2P | Danh tính, tài khoản cấp vốn, đích đến, thiết bị, IP, thời gian |
| Sổ cái | Bất kỳ ai chạy công cụ phân tích | Địa chỉ/đầu ra, số tiền và thời gian trên các blockchain minh bạch; metadata riêng theo giao thức ở những nơi khác |
| Backend ví | Nhà cung cấp RPC, trình khám phá blockchain, node từ xa | Truy vấn địa chỉ, số dư, IP, phát tán giao dịch |
| Mạng | ISP, peer, điểm vào mạng ẩn danh | IP, thời điểm, lưu lượng và việc sử dụng giao thức |
| Bên giao dịch | Người trả/người nhận | Hóa đơn/địa chỉ, giao hàng, trao đổi, tài khoản và thời điểm |
| Endpoint | Malware, bản sao lưu đám mây, thu giữ vật lý | Seed, khóa, nhãn, lịch sử, ảnh chụp màn hình và clipboard |

Tự lưu ký có thể loại bỏ bên lưu ký khỏi luồng kiểm soát nhưng không xóa sổ cái, hồ sơ mua vào, metadata mạng hay bằng chứng trên endpoint.

## So sánh giao thức

| Phương thức | Đặc tính quyền riêng tư hữu ích | Giới hạn quan trọng |
|---|---|---|
| Bitcoin on-chain | Tự lưu ký; địa chỉ mới tránh việc dùng lại địa chỉ đơn giản | Đồ thị giao dịch công khai và tồn tại vĩnh viễn; các heuristic về số tiền/thời điểm và cách chi tiêu |
| Bitcoin PayJoin | Đầu vào của người nhận có thể phá vỡ heuristic phổ biến cho rằng mọi đầu vào đều thuộc cùng một chủ sở hữu | Cả hai ví cần hỗ trợ; giao dịch vẫn công khai; mức hỗ trợ không đồng đều |
| Bitcoin CoinJoin | Tạo ra sự mơ hồ giữa những người tham gia phối hợp | Mẫu dễ nhận diện, liên kết trước/sau, hợp nhất, rủi ro về chính sách/pháp lý/nhà cung cấp |
| Lightning | Các khoản thanh toán được định tuyến onion không được công bố toàn mạng như các giao dịch thông thường | Mở/đóng channel được ghi on-chain; endpoint, peer, hoạt động dò tìm hoặc bên lưu ký có thể suy luận dữ liệu |
| Monero | Mặc định bảo mật on-chain mạnh hơn đối với người nhận, số tiền và tập hợp người gửi | Liên kết từ sàn giao dịch, node, thời điểm, endpoint và bên giao dịch vẫn tồn tại |
| Ethereum/stablecoin | Khả năng phổ biến rộng và tương tác với smart contract | Trạng thái/hoạt động công khai; metadata RPC; nhà phát hành tập trung có thể chặn/đóng băng/báo cáo |

## Bitcoin: thiết lập cơ bản bảo vệ quyền riêng tư

Bitcoin là giả danh, không phải ẩn danh. Các giao dịch đã xác nhận đều công khai và tồn tại lâu dài; việc dùng lại địa chỉ, quyền sở hữu đầu vào chung, phát hiện tiền thối lại và các địa chỉ được xác định công khai có thể giúp tạo cụm.<sup>[[1]](#references)</sup>

### Quy trình

1. **Chọn ví tự lưu ký được duy trì cập nhật.** Tải từ dự án chính thức, xác minh chữ ký/hash nếu có và cài đặt các bản cập nhật bảo mật.
2. **Tạo ví trên endpoint đáng tin cậy.** Ghi seed khôi phục ra phương tiện ngoại tuyến; không bao giờ lưu seed trong email, chat, ảnh chụp màn hình hay ghi chú đám mây thông thường. Thử khôi phục trước khi lưu trữ giá trị đáng kể.
3. **Chỉ giữ giá trị dùng cho hoạt động thường ngày trong ví nóng.** Dùng hình thức lưu ký ngoại tuyến/phần cứng phù hợp cho giá trị dài hạn, kèm kế hoạch khôi phục không để seed phụ thuộc vào một vị trí dễ gặp sự cố duy nhất.
4. **Tạo địa chỉ nhận/hóa đơn mới cho mỗi giao dịch.** Không công khai địa chỉ tĩnh nếu có thể dùng máy chủ hóa đơn hoặc phương thức gửi riêng có xác thực.
5. **Nếu khả thi, hãy dùng full node của riêng bạn.** Trình khám phá bên thứ ba/máy chủ electrum có thể biết các địa chỉ được truy vấn và metadata IP. Chỉ cấu hình hành vi Tor/proxy mà ví hỗ trợ; Tor ẩn một điểm kết nối mạng, không ẩn đồ thị blockchain.
6. **Gắn nhãn riêng cho từng UTXO** với nguồn, chủ sở hữu, mục đích và trạng thái tuân thủ. Bật coin control để tránh chi tiêu chung các khoản thuộc những ngữ cảnh danh tính không liên quan.
7. **Xem trước giao dịch:** các đầu vào được chọn, đích đến của tiền thối lại, số tiền, phí, bên giao dịch và liệu giao dịch có gộp các ngăn tách biệt hay không. Tránh hợp nhất không cần thiết.
8. **Lưu riêng các hồ sơ hợp pháp và mã hóa chúng.** Lưu căn cứ xác định giá vốn, hóa đơn, giấy phép và thông tin thuế/báo cáo mà không công khai mối liên hệ.
9. **Xem việc chi tiêu về sau là một phần của cùng quyết định bảo vệ quyền riêng tư.** Một khoản nhận được tách biệt tốt vẫn có thể bị liên kết lại khi đầu ra của nó được chi tiêu cùng với tiền đã xác định danh tính.

Tài liệu quyền riêng tư của Bitcoin Core giải thích rằng full node tránh tiết lộ các truy vấn ví cho máy chủ bên thứ ba, nhưng việc phát tán giao dịch và lịch sử công khai vẫn cần được phân tích.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin là hình thức thanh toán phối hợp, trong đó người nhận thêm một đầu vào. Điều này đánh bại giả định đơn giản rằng mọi đầu vào đều thuộc về người gửi. BIP 78 mô tả giao thức tương tác ban đầu; bản nháp BIP 77 định nghĩa thiết kế v2 bất đồng bộ sử dụng hộp thư được mã hóa/OHTTP.<sup>[[3]](#references)</sup>

Sử dụng an toàn:

1. Xác nhận cả hai ví được duy trì cập nhật và hỗ trợ cùng một phiên bản PayJoin.
2. Nhận hóa đơn hỗ trợ PayJoin qua kênh đã xác thực; bảo vệ hóa đơn như mọi yêu cầu thanh toán khác.
3. Kiểm tra số tiền và đích đến ban đầu, sau đó để ví xác thực đề xuất/PSBT, phần phí đóng góp và các thay đổi bị cấm.
4. Xác nhận phần tóm tắt giao dịch cuối cùng trong ví. Không phê duyệt thủ công đầu ra, số tiền hay mức phí quá cao nếu không mong đợi.
5. Nếu quá trình thương lượng thất bại, hãy hiểu ví có tự chuyển an toàn sang thanh toán thông thường hay yêu cầu hóa đơn mới.
6. Lưu riêng biên nhận/hồ sơ cần thiết cho việc xác nhận quyền sở hữu, kế toán và giải quyết tranh chấp.

PayJoin cải thiện một heuristic phân tích blockchain; nó không ẩn khoản thanh toán khỏi các bên liên quan, nền tảng mua vào, endpoint hay sổ cái công khai.

## CoinJoin: lợi ích và giới hạn

CoinJoin phối hợp nhiều người dùng trong một giao dịch để khiến việc ánh xạ đầu vào-đầu ra kém chắc chắn hơn. Nghiên cứu về các thiết kế Wasabi và Samourai cụ thể trong quá khứ phát hiện các giao dịch có mẫu rất dễ nhận diện, đồng thời cho thấy hành vi trước/sau khi trộn có thể thu hẹp đáng kể tính ẩn danh.<sup>[[4]](#references)</sup> Không nên khái quát kết quả đó cho mọi cách triển khai hay phiên bản tương lai, nhưng nó cho thấy con số “tập hợp ẩn danh” không phải là sự đảm bảo.

Trước khi sử dụng hợp pháp:

- kiểm tra luật hiện hành tại địa phương, tình trạng trừng phạt, chính sách của sàn/bên lưu ký và nghĩa vụ thuế/báo cáo;
- sử dụng phần mềm không lưu ký được duy trì cập nhật và tải từ dự án chính thức;
- tìm hiểu mô hình coordinator, phí, biện pháp kiểm soát từ chối dịch vụ và liệu dịch vụ hiện còn hoạt động hay không—zkSNACKs đã ngừng coordinator của mình vào năm 2024, dù có thể vẫn còn các coordinator Wasabi khác;
- lưu riêng hồ sơ nguồn tiền và giao dịch;
- không bao giờ nhận tiền không rõ nguồn gốc thay cho người khác hoặc dùng “mixer” lưu ký hứa hẹn rút tiền không thể truy vết;
- giữ các đầu ra tách biệt theo nguồn/ngữ cảnh và tránh hợp nhất về sau làm mất đi sự mơ hồ dự định tạo ra.

Kết quả pháp lý phụ thuộc vào tình tiết và khu vực tài phán. Các lời nhận tội của Samourai năm 2025 liên quan đến việc cố ý vận hành dịch vụ chuyển tiền không giấy phép, qua đó chuyển tiền thu được từ hoạt động phạm pháp; điều này không có nghĩa mọi giao dịch phối hợp hay người dùng muốn bảo vệ quyền riêng tư đều phạm tội.<sup>[[5]](#references)</sup>

## Lightning Network

Định tuyến onion Sphinx của Lightning được thiết kế để mỗi hop trung gian biết peer trước và sau nó, thay vì biết toàn bộ tuyến đường.<sup>[[6]](#references)</sup> Đây không phải là ẩn danh toàn diện: việc cấp vốn/đóng channel là công khai, node quảng bá cấu trúc mạng, các bên giao dịch biết endpoint, hoạt động định tuyến/dò tìm có thể suy luận số dư hoặc các bên, và ví lưu ký biết hoạt động tài khoản của người dùng.

Để tăng cường quyền riêng tư:

1. Nếu quyền riêng tư trước bên trung gian quan trọng, hãy ưu tiên ví không lưu ký được duy trì cập nhật; lên kế hoạch sao lưu/khôi phục channel trước.
2. Dùng hóa đơn hoặc offer mới cho mỗi khoản thanh toán. Xác minh ví cụ thể có hỗ trợ BOLT 12/route blinding hay không, đừng mặc định là có.
3. Tránh công khai alias node, thông tin liên hệ và endpoint mạng ổn định không cần thiết.
4. Nếu phù hợp, hãy kết nối qua mạng bảo vệ quyền riêng tư được hỗ trợ, đồng thời hiểu rằng các mẫu về thời gian hoạt động/thời điểm vẫn có thể được đối chiếu.
5. Đừng cho rằng thanh toán off-chain không để lại hồ sơ: người gửi, người nhận, peer, watchtower, nhà cung cấp thanh khoản và dịch vụ ví có thể lưu lại dữ liệu quan sát được.

Các nghiên cứu đã công bố chứng minh có thể suy luận người gửi/người nhận và số dư channel từ dữ liệu công khai cùng hoạt động dò tìm chủ động, dù các tấn công và biện pháp giảm thiểu vẫn tiếp tục thay đổi.<sup>[[7]](#references)</sup>

## Monero

Monero dùng địa chỉ stealth dùng một lần cho đầu ra, RingCT để ẩn số tiền và chữ ký vòng để tạo sự mơ hồ xác suất về người gửi; thông số kỹ thuật hiện tại của dự án ghi nhận kích thước vòng là 16 (15 decoy).<sup>[[8]](#references)</sup> Đây là các mặc định bảo mật on-chain mạnh hơn so với sổ cái minh bạch, chứ không phải biện pháp bảo vệ kỳ diệu trước sai sót ở endpoint hoặc trong vận hành.

### Quy trình hợp pháp

1. **Mua hợp pháp.** Sàn giao dịch chịu sự quản lý có thể biết giao dịch mua và rút tiền ngay cả khi các chi tiết on-chain về sau được bảo mật. Lưu hồ sơ về nguồn tiền, căn cứ xác định giá vốn và báo cáo.
2. **Cài đặt ví chính thức được duy trì cập nhật** và xác minh bản tải xuống theo hướng dẫn của dự án. Sao lưu seed ngoại tuyến và thử khôi phục với số tiền nhỏ.
3. **Ưu tiên node cục bộ** để tối đa hóa quyền riêng tư của các truy vấn ví. Nếu không khả thi, hãy chọn node từ xa đáng tin cậy có thể truy cập qua cấu hình onion/I2P được hỗ trợ chính thức. Node từ xa có thể ghi lại IP, yêu cầu, thời điểm và ID giao dịch; một số thiết kế nhẹ tiết lộ view key.
4. **Dùng subaddress mới cho mỗi người trả, chiến dịch hoặc hóa đơn.** Người trả có thể liên kết các lần sử dụng lặp lại cùng một subaddress.<sup>[[9]](#references)</sup>
5. **Gắn nhãn các ngữ cảnh nhận tiền cục bộ.** Tránh gộp các khoản nhận đã tách biệt trong vận hành nếu người trả am hiểu có thể nhận ra hành vi tiếp theo.
6. **Bảo vệ metadata mạng.** Làm theo cấu hình mạng ẩn danh chính thức; lưu ý các leak đã được ghi nhận từ timestamp, đồng bộ không liên tục, đặc điểm lưu lượng băng thông và việc tái sử dụng luồng kết nối.<sup>[[10]](#references)</sup>
7. **Giữ riêng dữ liệu tuân thủ/kiểm toán.** Chỉ tiết lộ view key hoặc bằng chứng giao dịch khi có chủ đích, cho đúng kiểm toán viên/bên nhận và sau khi hiểu chính xác thông tin được tiết lộ.

Các nghiên cứu truy vết trong quá khứ bao gồm những lỗi và giai đoạn lựa chọn decoy đã thay đổi; không áp dụng tỷ lệ thành công cũ cho giao dịch hiện tại. Tương tự, tính đến mốc nghiên cứu tháng 9 năm 2026 của chương này, FCMP++ vẫn là công việc trong lộ trình, chưa phải biện pháp bảo vệ đã triển khai.<sup>[[11]](#references)</sup>

## Ethereum và stablecoin

Tài liệu quyền riêng tư của Ethereum lưu ý rằng các hành động on-chain đều hiển thị và cơ sở hạ tầng ví/RPC làm lộ thêm IP cùng metadata.<sup>[[12]](#references)</sup> Chuyển token, phê duyệt, tương tác với smart contract, dịch vụ tên miền và cấp vốn gas đều có thể liên kết danh tính.

Stablecoin tập trung bổ sung quyền kiểm soát của nhà phát hành. Điều khoản USDC và Tether hiện hành có quy định về quyền chặn/đóng băng địa chỉ hoặc tài sản và tuân thủ các nghĩa vụ pháp lý/thủ tục.<sup>[[13]](#references)</sup> Chúng có thể hữu ích như công cụ thanh toán, nhưng không phù hợp nếu yêu cầu là chống kiểm duyệt hoặc ẩn danh on-chain.

## Ranh giới tuân thủ

- Các khuyến nghị của FATF được áp dụng thông qua luật quốc gia và thay đổi theo thời gian; bản cập nhật năm 2026 nhấn mạnh việc cấp phép/đăng ký VASP và triển khai Travel Rule.<sup>[[14]](#references)</sup>
- Tại Hoa Kỳ, FinCEN phân biệt người dùng tiền ảo chuyển đổi để mua hàng hóa/dịch vụ cho riêng mình với doanh nghiệp chấp nhận và chuyển tiền hoặc trao đổi tiền; tình tiết cụ thể và các quy định ban hành sau đó đều quan trọng.<sup>[[15]](#references)</sup>
- Quy định Chuyển tiền của EU yêu cầu thông tin người khởi tạo/người thụ hưởng khi có nhà cung cấp dịch vụ tài sản mã hóa tham gia, đồng thời bổ sung quy tắc xác minh cho một số giao dịch đến/từ địa chỉ tự lưu trữ.<sup>[[16]](#references)</sup>
- Nghĩa vụ về lệnh trừng phạt và thuế vẫn tiếp tục áp dụng. Thực hiện sàng lọc theo yêu cầu, từ chối các bên bị cấm và lưu hồ sơ; danh sách và tình trạng pháp lý có thể thay đổi nhanh chóng.<sup>[[17]](#references)</sup>

Trước khi xử lý giá trị đáng kể, hoạt động xuyên biên giới, phối hợp tăng cường quyền riêng tư hoặc hoạt động trao đổi/chuyển tiền mang tính kinh doanh, hãy xin tư vấn chuyên môn cập nhật cho các khu vực tài phán liên quan.

Để tìm hiểu Bitcoin Silent Payments, Zcash được che chắn hoàn toàn, GNU Taler, e-cash Chaumian liên kết liên bang và BOLT 12, hãy tiếp tục đến [Các giao thức thanh toán bảo vệ quyền riêng tư](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Bảo vệ quyền riêng tư của bạn](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Tính năng quyền riêng tư](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Đề xuất Payjoin đơn giản](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz và cộng sự — Mức độ chấp nhận và quyền riêng tư thực tế của các cách triển khai CoinJoin phi tập trung trong Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [Bộ Tư pháp Hoa Kỳ — Những người sáng lập Samourai Wallet nhận tội (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Giao thức định tuyến Onion](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos và cộng sự — Phân tích thực nghiệm về quyền riêng tư trong Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Địa chỉ stealth](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Chữ ký vòng](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) và [Thông số kỹ thuật](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Mạng](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad và Victor — Khảo sát sự phát triển của quyền riêng tư trong Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Quyền riêng tư trên Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Điều khoản USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Bản cập nhật có mục tiêu năm 2026 về tài sản ảo và VASP](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Áp dụng các quy định của FinCEN đối với người quản lý, trao đổi hoặc sử dụng tiền ảo](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Quy định (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [OFAC Hoa Kỳ — Hướng dẫn tuân thủ lệnh trừng phạt dành cho ngành tiền ảo](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
