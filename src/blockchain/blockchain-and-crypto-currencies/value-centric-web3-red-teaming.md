# Red Teaming Web3 lấy giá trị làm trọng tâm (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) phân loại các hành động và kỹ thuật đối kháng nhắm vào hệ thống tài sản số.<sup>[[1]](#references)</sup> Hãy xem framework này là **khung xương sống cho threat modeling**: liệt kê mọi thành phần có thể phát hành, định giá, cấp quyền hoặc định tuyến tài sản, ánh xạ các điểm tiếp xúc đó với kỹ thuật AADAPT, rồi xây dựng các kịch bản red-team để đánh giá khả năng chống chịu của môi trường trước tổn thất kinh tế không thể đảo ngược.

## 1. Kiểm kê các thành phần nắm giữ giá trị
Lập bản đồ mọi thứ có thể ảnh hưởng đến trạng thái giá trị, kể cả khi nằm ngoài chuỗi.<sup>[[2]](#references)</sup>

- **Dịch vụ ký lưu ký** (cụm HSM/KMS, Vault/KMaaS, API ký được bot hoặc tác vụ back-office sử dụng). Ghi lại ID khóa, chính sách, danh tính tự động hóa và quy trình phê duyệt.
- **Đường dẫn quản trị và nâng cấp** cho contract (proxy admin, governance timelock, khóa tạm dừng khẩn cấp, registry tham số). Ghi rõ ai/cái gì có thể gọi chúng, và cần quorum hoặc độ trễ nào.
- **Logic protocol on-chain** xử lý lending, AMM, vault, staking, bridge hoặc đường ray thanh toán. Ghi lại các bất biến mà chúng giả định (giá oracle, tỷ lệ tài sản thế chấp, tần suất tái cân bằng…).
- **Tự động hóa off-chain** tạo giao dịch (bot tạo lập thị trường, pipeline CI/CD, cron job, hàm serverless). Các thành phần này thường nắm API key hoặc service principal có thể yêu cầu chữ ký.
- **Oracle và data feed** (cấu thành aggregator, quorum, ngưỡng độ lệch, tần suất cập nhật). Ghi chú mọi upstream mà logic rủi ro tự động phụ thuộc vào.
- **Bridge và bộ định tuyến cross-chain** (contract lock/mint, relayer, tác vụ thanh toán) kết nối các chain hoặc hệ thống lưu ký.

Sản phẩm bàn giao: sơ đồ luồng giá trị thể hiện cách tài sản di chuyển, ai cấp quyền di chuyển và tín hiệu bên ngoài nào ảnh hưởng đến logic nghiệp vụ.

## 2. Ánh xạ thành phần với hành vi AADAPT
Chuyển taxonomy AADAPT thành các hướng tấn công cụ thể cho từng thành phần.<sup>[[2]](#references)</sup>

| Thành phần | Trọng tâm AADAPT chính |
| --- | --- |
| Hệ thống ký/KMS | Đánh cắp thông tin xác thực, vượt qua chính sách, lạm dụng ký, chiếm quyền governance |
| Oracle/feed | Đầu độc dữ liệu đầu vào, thao túng tổng hợp, né ngưỡng độ lệch |
| Protocol on-chain | Thao túng kinh tế bằng flash loan, phá vỡ bất biến, cấu hình lại tham số |
| Pipeline tự động hóa | Danh tính bot/CI bị xâm phạm, phát lại theo lô, triển khai trái phép |
| Bridge/bộ định tuyến | Né tránh cross-chain, rửa tiền qua nhiều bước nhanh chóng, mất đồng bộ thanh toán |

Việc ánh xạ này đảm bảo bạn kiểm thử không chỉ contract, mà cả mọi danh tính/tự động hóa có thể gián tiếp điều hướng giá trị.

## 3. Ưu tiên theo tính khả thi đối với kẻ tấn công và tác động kinh doanh

1. **Điểm yếu vận hành**: thông tin xác thực CI bị lộ, IAM role quá nhiều quyền, chính sách KMS cấu hình sai, tài khoản tự động hóa có thể yêu cầu chữ ký tùy ý, bucket công khai chứa cấu hình bridge, v.v.
2. **Điểm yếu đặc thù giá trị**: tham số oracle mong manh, contract có thể nâng cấp nhưng không yêu cầu phê duyệt nhiều bên, thanh khoản nhạy cảm với flash loan, hành động governance bỏ qua timelock.

Xử lý danh sách như một đối thủ: bắt đầu từ các điểm xâm nhập vận hành có thể thành công ngay hôm nay, rồi chuyển sang các đường thao túng kinh tế/protocol chuyên sâu.<sup>[[2]](#references)</sup>

## 4. Thực thi trong môi trường được kiểm soát, sát thực tế production
- **Mainnet fork/testnet cô lập**: tái tạo bytecode, storage và thanh khoản để các đường flash loan, biến động oracle và luồng bridge có thể chạy từ đầu đến cuối mà không động đến tiền thật.<sup>[[2]](#references)</sup>
- **Lập kế hoạch phạm vi ảnh hưởng**: xác định circuit breaker, module có thể tạm dừng, runbook rollback và admin key chỉ dùng để kiểm thử trước khi kích hoạt kịch bản.
- **Phối hợp với các bên liên quan**: thông báo cho đơn vị lưu ký, đơn vị vận hành oracle, đối tác bridge và bộ phận compliance để đội giám sát của họ dự liệu lưu lượng.
- **Phê duyệt pháp lý**: ghi lại phạm vi, sự cho phép và điều kiện dừng khi mô phỏng có thể chạm đến các đường ray chịu quản lý.

## 5. Telemetry phù hợp với kỹ thuật AADAPT
Thiết lập các luồng telemetry để mỗi kịch bản tạo ra dữ liệu phát hiện có thể hành động.<sup>[[2]](#references)</sup>

- **Trace cấp chain**: toàn bộ call graph, lượng gas sử dụng, nonce giao dịch, timestamp của block—để tái dựng các bundle flash loan, cấu trúc giống reentrancy và các bước nhảy giữa contract.
- **Log ứng dụng/API**: liên kết mỗi giao dịch on-chain với danh tính người dùng hoặc tự động hóa (session ID, OAuth client, API key, CI job ID), kèm IP và phương thức xác thực.
- **Log KMS/HSM**: key ID, caller principal, kết quả chính sách, địa chỉ đích và mã lý do cho mỗi chữ ký. Thiết lập baseline cho khung thời gian thay đổi và thao tác rủi ro cao.
- **Metadata oracle/feed**: thành phần nguồn dữ liệu theo từng lần cập nhật, giá trị được báo cáo, độ lệch so với trung bình trượt, ngưỡng được kích hoạt và các đường chuyển đổi dự phòng đã sử dụng.
- **Trace bridge/swap**: liên kết các sự kiện lock/mint/unlock giữa các chain bằng correlation ID, chain ID, danh tính relayer và thời gian giữa các bước.
- **Dấu hiệu bất thường**: các chỉ số suy ra như đột biến slippage, tỷ lệ tài sản thế chấp bất thường, mật độ gas khác thường hoặc tốc độ di chuyển cross-chain.

Gắn scenario ID hoặc synthetic user ID cho mọi thứ để analyst có thể đối chiếu dữ liệu quan sát với kỹ thuật AADAPT đang được kiểm thử.

## 6. Vòng lặp purple-team và chỉ số trưởng thành
1. Chạy kịch bản trong môi trường được kiểm soát và thu thập kết quả phát hiện (cảnh báo, dashboard, thông báo đến responder).<sup>[[2]](#references)</sup>
2. Ánh xạ từng bước với kỹ thuật AADAPT cụ thể cùng dữ liệu quan sát được trong các lớp chain/app/KMS/oracle/bridge.
3. Xây dựng và triển khai giả thuyết phát hiện (quy tắc ngưỡng, truy vấn tương quan, kiểm tra bất biến).
4. Chạy lại cho đến khi mean time to detect (MTTD) và mean time to contain (MTTC) đáp ứng ngưỡng chấp nhận của doanh nghiệp, đồng thời playbook có thể ngăn thất thoát giá trị một cách đáng tin cậy.

Theo dõi mức độ trưởng thành của chương trình trên ba trục:<sup>[[2]](#references)</sup>
- **Khả năng quan sát**: mọi đường dẫn giá trị quan trọng đều có telemetry ở từng lớp.
- **Độ bao phủ**: tỷ lệ các kỹ thuật AADAPT được ưu tiên đã kiểm thử từ đầu đến cuối.
- **Khả năng ứng phó**: khả năng tạm dừng contract, thu hồi key hoặc đóng băng luồng trước khi xảy ra tổn thất không thể đảo ngược.

Các mốc điển hình: (1) hoàn tất kiểm kê giá trị và ánh xạ AADAPT, (2) kịch bản đầu tiên từ đầu đến cuối có phát hiện được triển khai, (3) các chu kỳ purple-team hàng quý mở rộng độ bao phủ và giảm MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Mẫu kịch bản
Dùng các bản thiết kế có thể lặp lại này để xây dựng mô phỏng ánh xạ trực tiếp với hành vi AADAPT.<sup>[[2]](#references)</sup>

### Kịch bản A – Thao túng kinh tế bằng flash loan
- **Mục tiêu**: vay vốn ngắn hạn trong một giao dịch để làm sai lệch giá/thanh khoản AMM và kích hoạt borrow, liquidation hoặc mint sai định giá trước khi hoàn trả.
- **Thực thi**:
  1. Fork chain mục tiêu và cấp thanh khoản gần với production cho các pool.
  2. Vay một khoản danh nghĩa lớn qua flash loan.
  3. Thực hiện các swap được hiệu chỉnh để vượt qua các ranh giới giá/ngưỡng mà logic lending, vault hoặc phái sinh phụ thuộc vào.
  4. Gọi contract mục tiêu ngay sau khi tạo sai lệch (borrow, liquidate, mint), rồi hoàn trả flash loan.
- **Đo lường**: Vi phạm bất biến có thành công không? Các bộ giám sát slippage/độ lệch giá, circuit breaker hoặc hook tạm dừng governance có được kích hoạt không? Mất bao lâu để analytics phát hiện mẫu gas/call graph bất thường?

### Kịch bản B – Đầu độc oracle/data feed
- **Mục tiêu**: xác định liệu feed bị thao túng có thể kích hoạt các hành động tự động gây thiệt hại (thanh lý hàng loạt, thanh toán sai) hay không.
- **Thực thi**:
  1. Trong fork/testnet, triển khai feed độc hại hoặc điều chỉnh trọng số aggregator/quorum/tần suất cập nhật vượt quá độ lệch cho phép.
  2. Để các contract phụ thuộc tiêu thụ giá trị bị đầu độc và chạy logic thông thường.
- **Đo lường**: Cảnh báo ngoài ngưỡng ở cấp feed, kích hoạt oracle dự phòng, thực thi giới hạn min/max và độ trễ từ lúc bất thường bắt đầu đến khi operator phản ứng.

### Kịch bản C – Lạm dụng thông tin xác thực/chữ ký
- **Mục tiêu**: kiểm thử xem việc xâm phạm một signer hoặc danh tính tự động hóa có cho phép nâng cấp, thay đổi tham số trái phép hoặc rút cạn treasury hay không.
- **Thực thi**:
  1. Liệt kê các danh tính có quyền ký nhạy cảm (operator, CI token, service account gọi KMS/HSM, thành viên multisig).
  2. Mô phỏng việc xâm phạm (sử dụng lại thông tin xác thực/key của họ trong phạm vi lab).
  3. Thử các hành động có đặc quyền: nâng cấp proxy, thay đổi tham số rủi ro, mint/tạm dừng tài sản hoặc kích hoạt đề xuất governance.
- **Đo lường**: Log KMS/HSM có tạo cảnh báo bất thường không (thời điểm trong ngày, thay đổi địa chỉ đích, đột biến thao tác rủi ro cao)? Chính sách hoặc ngưỡng multisig có ngăn được việc lạm dụng đơn phương không? Có áp dụng throttling/rate limit hoặc phê duyệt bổ sung không?

### Kịch bản D – Né tránh cross-chain và khoảng trống truy vết
- **Mục tiêu**: đánh giá khả năng truy vết và ngăn chặn tài sản được rửa nhanh qua bridge, DEX router và các bước chuyển qua dịch vụ bảo mật của đội phòng thủ.
- **Thực thi**:
  1. Nối tiếp các thao tác lock/mint qua những bridge phổ biến, xen kẽ swap/mixer trên mỗi chặng và duy trì correlation ID cho từng chặng.
  2. Tăng tốc độ chuyển để gây áp lực lên độ trễ giám sát (nhiều bước chuyển trong vài phút/block).
- **Đo lường**: Thời gian tương quan sự kiện giữa telemetry và phân tích chain thương mại, mức độ đầy đủ của đường đi được tái dựng, khả năng xác định điểm nghẽn để đóng băng trong sự cố thực tế, và độ chính xác của cảnh báo về tốc độ/giá trị cross-chain bất thường.

## References

- [1] [Framework MITRE AADAPT(TM) về mối đe dọa mạng đối với tài sản số](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Framework MITRE AADAPT như lộ trình Red Team](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
