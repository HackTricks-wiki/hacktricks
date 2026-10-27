# Thủ thuật che giấu tài chính

{{#include ../banners/hacktricks-training.md}}

Quyền riêng tư trong thanh toán là vấn đề quy kết, không phải vấn đề thương hiệu thanh toán. Một chiến dịch để lại bằng chứng khi giá trị được thu nhận, luân chuyển, chuyển đổi, chi tiêu và giao nhận. Địa chỉ trên blockchain công khai có thể mang tính bút danh, trong khi sàn giao dịch, đơn vị phát hành thẻ, người bán, thiết bị di động hoặc camera giao hàng có thể xác định người đứng sau địa chỉ đó.

Trang này giải thích các mô hình che giấu tài chính được sử dụng trong tội phạm mạng và các chiến dịch có liên hệ với nhà nước để giúp lực lượng phòng thủ nhận diện chúng. Trang **không** hướng dẫn quy trình rửa tiền, né tránh lệnh trừng phạt, sử dụng danh tính giả hoặc vượt qua KYC.

## Sơ đồ luân chuyển giá trị đầu-cuối

```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
      |              |                |                 |             |
 bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```

Một tác nhân cố ngăn mọi người quan sát nhìn thấy cả hai đầu. Điều tra viên làm ngược lại: lưu giữ hồ sơ ở mỗi ranh giới, chuẩn hóa thời gian/giá trị/phí và xác định **điểm hội tụ lại** nơi các danh tính khác nhau dùng chung một bên trung gian, thiết bị, tài khoản, đơn vị bán hàng hoặc điểm đến.

## Công cụ và những bên thực sự quan sát được chúng

| Công cụ | Ẩn với đơn vị bán hàng/công chúng | Vẫn hiển thị với |
|---|---|---|
| Thẻ ảo/token của tổ chức phát hành | số thẻ cơ sở | tổ chức phát hành, mạng lưới/bên cung cấp token, ví, tài khoản của đơn vị bán hàng và hệ thống giao nhận |
| Giá trị trả trước/thẻ quà tặng | đôi khi là tên pháp lý khi mua thông thường | nhà bán lẻ/đường ray thanh toán, dịch vụ kích hoạt/đổi, camera, thiết bị và giao nhận |
| Tiền mặt | sổ cái công khai và tổ chức phát hành từ xa | các bên giao dịch, camera, cơ chế kiểm soát rút tiền/số sê-ri nếu có, khám xét thực địa |
| Bitcoin/địa chỉ mới | tên pháp lý trực tiếp | mọi bên quan sát blockchain; các peer của ví/mạng; dịch vụ mua vào/rút ra |
| CoinJoin/PayJoin | các heuristic đơn giản dựa trên đầu vào chung/thanh toán | giao dịch công khai, metadata của coordinator/peer/mạng và hành vi chi tiêu về sau |
| Privacy coin | người gửi/người nhận/số tiền công khai, tùy giao thức | dịch vụ mua vào/rút ra, endpoint của ví, bên quan sát mạng và đối tác giao dịch |
| Mixer tập trung | liên kết gửi vào-rút ra trực tiếp | đơn vị vận hành/log của mixer, các tập hợp đầu vào/đầu ra trên blockchain và đối tác giao dịch |
| Cầu nối/hoán đổi cross-chain | tính liên tục trên một chain | cả hai chain, dịch vụ cầu nối/hoán đổi, các ràng buộc về thời gian/giá trị và thanh khoản |
| Môi giới OTC/P2P | tài khoản sàn giao dịch trực tiếp trong một số trường hợp | môi giới, liên lạc, dòng tiền ngân hàng/tiền mặt, đối tác giao dịch và thiết bị |

## Thẻ, giá trị trả trước, người đứng tên hộ và mule

### Thẻ ảo và thẻ được che thông tin

Tổ chức phát hành có thể tạo số thẻ chỉ dùng với một đơn vị bán hàng hoặc dùng một lần. Điều này giảm mức độ đơn vị bán hàng tiếp xúc với thông tin thẻ và ngăn việc tái sử dụng số thẻ giữa nhiều đơn vị bán hàng. Tổ chức phát hành vẫn liên kết số thẻ đó với khách hàng, tài khoản nạp tiền, thiết bị, IP và giao dịch. Mô tả giao dịch trên sao kê, tài khoản của đơn vị bán hàng, địa chỉ giao hàng và dữ liệu trình duyệt vẫn có thể liên kết được.

Quảng cáo thẻ “không tên” không đồng nghĩa với thanh toán ẩn danh. Các tổ chức phát hành và nhà phân phối chịu sự quản lý có thể kiểm tra danh tính, lưu hồ sơ, áp giới hạn địa lý/số tiền và đáp ứng yêu cầu pháp lý. Có được thẻ bằng danh tính bị đánh cắp là hành vi đánh cắp danh tính; việc đó không xóa dữ liệu theo dõi của tổ chức phát hành/thiết bị/đơn vị bán hàng.

### Giá trị trả trước và thẻ quà tặng

Thẻ trả trước và mã quà tặng tách lần đổi về sau khỏi công cụ thanh toán ban đầu, nhưng tạo ra một vật thể có số định danh cùng các sự kiện mua, kích hoạt, truy vấn số dư và đổi. Các mô hình đáng chú ý gồm mua số lượng lớn, lặp lại các mệnh giá ngay dưới ngưỡng kiểm soát, đổi nhanh ở nơi xa, dùng một thiết bị kiểm tra nhiều số dư hoặc nhiều thẻ cùng hội tụ về một đơn vị bán hàng/tài khoản.

### Người đứng tên hộ, mule chuyển tiền và doanh nghiệp bình phong

Người đứng tên hộ hoặc mule cung cấp tài khoản và danh tính pháp lý nằm giữa người điều hành và dịch vụ. Các mạng lưới có thể thêm nhiều tầng gồm người tuyển mộ, chủ tài khoản, đơn vị xử lý thanh toán, doanh nghiệp bình phong và môi giới rút tiền. Cách này tạo khoảng cách, nhưng mỗi người tham gia lại tạo thêm liên lạc, phí, điểm bất nhất trong hành vi và nguy cơ trở thành nhân chứng hợp tác. Doanh nghiệp bình phong tạo thêm hồ sơ thành lập, thuế, ngân hàng, giám đốc, hóa đơn, lưu trữ và vận chuyển.

Bên phòng thủ nên điều tra các thiết bị/IP dùng chung, việc tái sử dụng người thụ hưởng, mâu thuẫn về vị trí địa lý, tốc độ giao dịch không phù hợp với lịch sử tài khoản, chuyển khoản vòng tròn, nhiều người gửi không liên quan cùng hội tụ và việc chuyển tiếp ngay lập tức. Đừng mặc định chủ tài khoản đứng tên là tác nhân kiểm soát; hãy xem họ là một nút cần xác định vai trò.

## Các mô hình che giấu giao dịch trên blockchain công khai

### Luân phiên địa chỉ và kiểm soát coin

Tạo địa chỉ mới cho mỗi lần nhận giúp tránh việc tái sử dụng địa chỉ một cách hiển nhiên, nhưng các giao dịch vẫn có thể liên kết quyền sở hữu thông qua đầu vào chung, nhận diện tiền thừa, giá trị/thời gian chính xác và việc hợp nhất về sau. **Kiểm soát coin** cho phép ví chọn các đầu ra cần chi tiêu và tránh gộp các ngăn tách biệt. Cách này cải thiện tính vệ sinh; nó không thể xóa một liên kết đã công khai.

### Chuỗi bóc tách

Chuỗi bóc tách liên tục chi tiêu một số dư lớn, gửi một khoản nhỏ hơn ra ngoài và trả phần còn lại về một địa chỉ mới:

```text
100 -> payment 3 + change 97
 97 -> payment 4 + change 93
 93 -> payment 2 + change 91 -> ...
```

Địa chỉ thay đổi ở mỗi bước, nhưng tính liên tục của giá trị, nhịp độ và cấu trúc giao dịch thường tạo thành một chuỗi dễ nhận diện. Ví nóng của các sàn giao dịch hợp pháp cũng có thể hoạt động tương tự, vì vậy việc quy kết cần có bằng chứng về dịch vụ/ngữ cảnh. DOJ đã sử dụng phân tích peel-chain trong các vụ tịch thu tài sản liên quan đến DPRK.<sup>[[1]](#references)</sup>

### Structuring và fan-out/fan-in

- **Fan-out:** một nguồn chia tiền sang nhiều địa chỉ để tăng khối lượng công việc điều tra hoặc chuẩn bị chuyển đổi song song.
- **Fan-in:** nhiều nguồn hợp nhất vào một địa chỉ thu gom, cho thấy khả năng có chung quyền kiểm soát hoặc sử dụng chung một dịch vụ.
- **Structuring:** các khoản chuyển nhỏ lặp đi lặp lại nhằm tránh ngưỡng rà soát hoặc hòa lẫn vào khối lượng giao dịch thông thường.
- **Commingling:** tiền bất hợp pháp và tiền không liên quan cùng nằm trong ví, pool hoặc dịch vụ, khiến các kết luận tỷ lệ đơn giản không đáng tin cậy.

Hình dạng đồ thị là manh mối, không phải bằng chứng. Các nhà phân tích nên tính đến phí, mô hình UTXO/tài khoản, hành vi của dịch vụ và quy ước địa chỉ tiền thừa.

### CoinJoin và PayJoin

Trong CoinJoin thông thường, nhiều người tham gia đóng góp các đầu vào và nhận các đầu ra trong một giao dịch cộng tác, thường với các mệnh giá đầu ra bằng nhau. Điều này phá vỡ giả định rằng mỗi đầu vào và đầu ra trong một giao dịch đều thuộc về cùng một chủ sở hữu. Tập ẩn danh bị giới hạn bởi số người tham gia và hành vi về sau: tiền thừa không bằng nhau, tiền thừa độc hại, việc hợp nhất hoặc đi qua một dịch vụ đã biết có thể làm lộ lại các mối liên kết.

PayJoin điều chỉnh một khoản thanh toán thông thường để cả bên trả và bên nhận đều đóng góp đầu vào, trực tiếp vô hiệu hóa heuristic về quyền sở hữu chung các đầu vào đối với giao dịch đó. Đây chủ yếu là giao thức bảo vệ quyền riêng tư thanh toán, không phải dịch vụ rửa tiền quy mô lớn. Việc phát hiện nên tránh tuyên bố rằng mọi đầu vào đều thuộc cùng một chủ sở hữu, đồng thời cần thể hiện sự không chắc chắn thay vì áp đặt một cụm sai lệch.

### Mixer và tumbler tập trung

Mixer tập trung nhận tiền gửi rồi thanh toán bằng các đồng coin khác từ một khoản dự trữ chung, thường sau khi trừ phí và chờ một khoảng thời gian. Khả năng bảo vệ quyền riêng tư phụ thuộc vào quy mô pool, chính sách rút tiền, nhật ký, sự trung thực của đơn vị vận hành và khả năng chống bị tịch thu. Phân tích thời gian/giá trị vào-ra, địa chỉ tiền gửi, việc gom cụm ví của dịch vụ và hồ sơ có thể thu hẹp tập hợp. Đơn vị vận hành có thể đánh cắp tiền hoặc giữ lại bảng ánh xạ đầy đủ.

Rủi ro pháp lý rất lớn và khác nhau tùy khu vực pháp lý. Các vụ việc của DOJ liên quan đến các nhà phát triển/đơn vị vận hành ChipMixer, Samourai Wallet và Tornado Cash, cùng các vụ kiện về lệnh trừng phạt đang diễn biến, cho thấy các yếu tố về giao thức, lưu ký, quyền kiểm soát và hoạt động chuyển tiền đều quan trọng; nhãn “phi tập trung” không phải là kết luận pháp lý.<sup>[[2]](#references)</sup>

### Chuyển chuỗi, hoán đổi và cầu nối xuyên chuỗi

Chuyển chuỗi biến đổi tài sản hoặc đưa tài sản qua một cầu nối, làm gián đoạn việc truy vấn trên một sổ cái duy nhất nhưng không làm mất tính liên tục về mặt kinh tế:

```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
        t0, amount A                    t1, amount B - fees
```

Các nhà phân tích đối chiếu hợp đồng bridge/địa chỉ nạp tiền của dịch vụ, thứ tự giao dịch, khung thời gian, tỷ giá, phí, thanh khoản và số tiền đặc trưng. Các lần swap lặp lại có thể làm tăng tính mơ hồ, đồng thời tạo thêm telemetry từ nhà cung cấp/API/ví. FATF đặc biệt xác định chain hopping, mixer, dịch vụ peer-to-peer và tiền mã hóa tăng cường tính ẩn danh là các chỉ báo rủi ro khi kết hợp với bối cảnh đáng ngờ.<sup>[[3]](#references)</sup>

### NFT, cờ bạc và giao dịch mua hàng hóa

Các giao dịch NFT tự mua bán hoặc thông đồng có thể tạo cho dòng tiền một câu chuyện bán hàng có vẻ hợp lý; cờ bạc có thể biến tiền nạp thành tiền rút; hàng hóa có thể chuyển đổi giá trị kỹ thuật số thành hàng tồn kho có thể bán lại. Các đường đi này để lại tài khoản trên marketplace, liên kết giữa người tạo và tiền bản quyền, đồ thị wash trading, lịch sử cược/lượt chơi, log thiết bị, bằng chứng giao hàng và bán lại. Khoản lỗ hay phí không chứng minh rằng nguồn gốc đã biến mất.

## Tiền mã hóa bảo vệ quyền riêng tư

Các giao thức bảo mật khác nhau về mặt kỹ thuật:

- **Monero** sử dụng địa chỉ dùng một lần, ring signature và số tiền bảo mật, giúp giảm khả năng nhìn thấy công khai người gửi/người nhận/số tiền. Việc quan sát mạng, ví bị xâm phạm, hoạt động mua vào/rút ra và hồ sơ của bên đối tác vẫn nằm ngoài các biện pháp bảo vệ trên chuỗi đó.
- **Zcash shielded pools** có thể che giấu người gửi, người nhận và số tiền khi sử dụng giao dịch shielded; địa chỉ transparent và các lần chuyển giữa các pool vẫn công khai, còn kiểu sử dụng ảnh hưởng đến tập ẩn danh thực tế.
- **Bitcoin** mặc định minh bạch. Địa chỉ mới, CoinJoin, PayJoin và Lightning thay đổi một số giả định về khả năng liên kết, nhưng không khiến mọi lớp đều riêng tư.

Công nghệ bảo mật có những ứng dụng chính đáng về an toàn và thương mại. Từ góc độ điều tra, khi sổ cái cung cấp ít thông tin hơn, bằng chứng từ endpoint, dịch vụ, mạng và con người trở nên quan trọng hơn. Không bao giờ suy luận rằng một người phạm tội chỉ dựa trên việc họ chọn giao thức bảo vệ quyền riêng tư.

## Mô hình vụ việc nhiều lớp của DPRK

Các cáo buộc công khai và vụ kiện tịch thu tài sản của DOJ mô tả một quy trình gồm nhiều phần, chứ không phải một thủ thuật duy nhất:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. người lao động sử dụng giấy tờ nhận dạng giả mạo/đánh cắp và VPN để có được công việc từ xa;
2. nhà tuyển dụng trả lương bằng tiền mã hóa, bao gồm stablecoin;
3. tiền được chuyển thành các khoản nhỏ hơn, qua các chain hoặc token khác, dùng mua NFT hoặc trộn lẫn với các khoản khác;
4. các khoản tiền bị đánh cắp khác được đưa vào mixer;
5. các nhà giao dịch OTC và công ty bình phong chuyển đổi giá trị thành khoản thanh toán hoặc hàng hóa bằng fiat;
6. các bên hỗ trợ, tài khoản và đường đi trên blockchain lặp lại giúp điều tra viên kết nối lại các lớp.

Treasury tuyên bố Lazarus đã dùng Blender.io để xử lý một phần số tiền từ vụ trộm Axie Infinity/Ronin, trong khi FBI đã công bố các địa chỉ và kêu gọi bridge, sàn giao dịch, đơn vị vận hành RPC và công ty phân tích chặn các khoản tiền liên quan đến những vụ trộm TraderTraitor sau đó.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Bài học có tính hai chiều: các tác nhân nhà nước sử dụng những dịch vụ thương mại/tội phạm thông thường, còn blockchain công khai cho phép bên phòng thủ theo dõi dòng giá trị ngay cả khi ban đầu chưa biết danh tính.

## Quy trình phát hiện

1. **Lưu giữ mã định danh và hồ sơ giao dịch thô.** Ảnh chụp màn hình và giá trị fiat đã làm tròn là không đủ.
2. **Chuẩn hóa tài sản và thời gian.** Ghi lại chain, hợp đồng token, đơn vị, thời gian khối, múi giờ của dịch vụ, phí và nguồn tỷ giá.
3. **Gắn nhãn độ tin cậy của bằng chứng.** Phân biệt địa chỉ do dịch vụ công bố, sự kiện hợp đồng có tính xác định, heuristic phân cụm và thông tin tình báo bên ngoài.
4. **Truy vết theo cả hai chiều.** Tìm nguồn tiền, phân tán ngay sau đó, hội tụ lại, các điểm rút khỏi bridge, khoản nạp vào dịch vụ và hoạt động chi tiêu/giao hàng.
5. **Đối chiếu bằng chứng ngoài chuỗi.** Hồ sơ KYC của tài khoản, thiết bị, IP, phiếu hỗ trợ, API key, hồ sơ ngân hàng/thanh toán, vận chuyển và liên lạc thường giúp làm rõ sự mơ hồ.
6. **Kiểm tra các cách giải thích khác.** Sàn giao dịch, đơn vị lưu ký, bảng lương và giao thức bảo mật có thể tạo ra fan-in/out hoặc co-spend mà không có cùng chủ sở hữu hưởng lợi.
7. **Tiếp tục giám sát thay vì kết luận quá sớm.** Một output không hoạt động có thể được quy kết khi sau này nó chuyển đến một dịch vụ.
8. **Áp dụng các nghĩa vụ trừng phạt/AML hiện hành với tư vấn pháp lý.** Quy định và danh sách chỉ định thay đổi; mối liên hệ trong quá khứ không thay thế cho phân tích pháp lý hiện tại.

## Mô hình mua sắm red-team an toàn

Một nhóm được ủy quyền có thể cần SOC của mục tiêu không nhận ra khoản thanh toán cho dịch vụ hosting là của họ, trong khi người kiểm soát hoạt động vẫn chịu trách nhiệm:

- sử dụng thẻ tổ chức dành riêng cho đợt engagement hoặc ví doanh nghiệp có hồ sơ chứng từ;
- đảm bảo hồ sơ thanh toán, thuế và nhà cung cấp chính xác;
- tách người vận hành khỏi nhiệm vụ mua sắm và giới hạn quyền truy cập vào sơ đồ quy kết;
- không bao giờ dùng mule, danh tính giả, thẻ bị đánh cắp, cách né tránh lệnh trừng phạt hoặc đơn vị đổi tiền không có giấy phép;
- ghi lại tài sản, số tiền, chủ sở hữu, dịch vụ, ngày tháng, phương án hoàn tiền và bằng chứng gỡ bỏ;
- sau cuộc diễn tập, tiết lộ cho người kiểm soát các chỉ báo liên quan đến thanh toán/nhà cung cấp.

Cách này tạo ra **sự không nhận biết về người tham gia diễn tập**, chứ không phải sự không nhận biết đối với pháp luật, nhà cung cấp hay cơ chế quản trị.

## References

- [1] [US DOJ — Khung thực thi về tiền mã hóa (ví dụ về peel-chain và các cuộc điều tra DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Chiến dịch triệt phá ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Các chỉ báo cảnh báo đỏ về tài sản ảo](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Đại diện Ngân hàng Ngoại thương DPRK bị buộc tội trong các âm mưu rửa tiền mã hóa](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Đơn kiện tịch thu dân sự liên quan đến 7,74 triệu USD bị cáo buộc rửa tiền cho DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Lệnh trừng phạt Blender.io và tiền của Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Triều Tiên chịu trách nhiệm về vụ trộm Bybit năm 2025](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Áp dụng quy định đối với người dùng, đơn vị quản trị và đơn vị đổi tiền ảo](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
