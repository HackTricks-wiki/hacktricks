# Blockchain và tiền mã hóa

{{#include ../../banners/hacktricks-training.md}}

Chương này trình bày các khái niệm về blockchain và bảo mật on-chain. Nếu gặp một Bitcoin peer bị lộ, hãy bắt đầu với [liệt kê dịch vụ Bitcoin P2P](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); nếu kiểm thử frontend trên trình duyệt, kết nối ví hoặc backend off-chain, hãy dùng [pentesting DApp](../../pentesting-web/dapps-DecentralizedApplications.md). Để tìm hiểu các hoạt động bảo mật quyền riêng tư của tiền mã hóa và những giới hạn của chúng, hãy xem [chương về quyền riêng tư của tiền mã hóa](../../privacy/cryptocurrency-privacy.md).

## Khái niệm cơ bản

- **Hợp đồng thông minh** là các chương trình được định nghĩa để thực thi trên blockchain khi đáp ứng một số điều kiện nhất định, tự động hóa việc thực hiện thỏa thuận mà không cần bên trung gian.
- **Ứng dụng phi tập trung (dApp)** được xây dựng dựa trên hợp đồng thông minh, có giao diện người dùng thân thiện và backend minh bạch, có thể kiểm toán.
- **Token và coin** khác nhau ở chỗ coin đóng vai trò như tiền kỹ thuật số, còn token đại diện cho giá trị hoặc quyền sở hữu trong các bối cảnh cụ thể.
  - **Utility token** cấp quyền truy cập vào dịch vụ, còn **security token** biểu thị quyền sở hữu tài sản.
- **DeFi** là viết tắt của Decentralized Finance, cung cấp dịch vụ tài chính mà không cần cơ quan trung ương.
- **DEX** và **DAO** lần lượt chỉ các nền tảng sàn giao dịch phi tập trung và các tổ chức tự trị phi tập trung.

Để tìm hiểu thuật ngữ về lệnh giao ngay, hợp đồng tương lai, đòn bẩy và quyền chọn trên thị trường crypto, xem [Thuật ngữ đầu tư](investment-terms.md).

## Cơ chế đồng thuận

Cơ chế đồng thuận đảm bảo các giao dịch trên blockchain được xác thực an toàn và thống nhất:

- **Proof of Work (PoW)** dựa vào năng lực tính toán để xác minh giao dịch.
- **Proof of Stake (PoS)** yêu cầu validator nắm giữ một lượng token nhất định, giúp giảm mức tiêu thụ năng lượng so với PoW.<sup>[[1]](#references)</sup>

## Kiến thức cơ bản về Bitcoin

### Giao dịch

Giao dịch Bitcoin chuyển tiền giữa các địa chỉ. Giao dịch được xác thực bằng chữ ký số, đảm bảo chỉ chủ sở hữu khóa riêng mới có thể khởi tạo giao dịch chuyển tiền.<sup>[[2]](#references)</sup>

#### Thành phần chính:

- **Giao dịch đa chữ ký** yêu cầu nhiều chữ ký để ủy quyền cho một giao dịch.<sup>[[3]](#references)</sup>
- Giao dịch gồm **inputs** (nguồn tiền), **outputs** (đích đến), **fees** (trả cho thợ đào) và **scripts** (quy tắc giao dịch).

### Lightning Network

Lightning Network nhằm cải thiện khả năng mở rộng của Bitcoin bằng cách cho phép thực hiện nhiều giao dịch trong một channel và chỉ phát trạng thái cuối cùng lên blockchain.

## Các vấn đề về quyền riêng tư của Bitcoin

Các cuộc tấn công vào quyền riêng tư, chẳng hạn như **suy luận quyền sở hữu chung các input** và **phát hiện địa chỉ nhận tiền thừa UTXO**, khai thác các mẫu giao dịch. Những phương pháp như **mixer** và **CoinJoin** tăng tính ẩn danh bằng cách che khuất mối liên hệ giao dịch giữa người dùng.

## Mua Bitcoin ẩn danh

Các phương pháp bao gồm giao dịch bằng tiền mặt, đào coin và sử dụng mixer. **CoinJoin** trộn nhiều giao dịch để làm phức tạp việc truy vết, còn **PayJoin** ngụy trang CoinJoin thành giao dịch thông thường để tăng cường quyền riêng tư.

# Tổng quan về các cuộc tấn công vào quyền riêng tư của Bitcoin

Trong thế giới Bitcoin, quyền riêng tư của giao dịch và tính ẩn danh của người dùng thường là những vấn đề đáng quan tâm. Dưới đây là tổng quan đơn giản về một số phương thức phổ biến mà kẻ tấn công có thể dùng để xâm phạm quyền riêng tư của Bitcoin.<sup>[[6]](#references)</sup>

## **Giả định quyền sở hữu chung các input**

Việc kết hợp các input của nhiều người dùng vào một giao dịch thường hiếm gặp do tính phức tạp của nó. Vì vậy, **hai địa chỉ input trong cùng một giao dịch thường được cho là thuộc về cùng một chủ sở hữu**.

## **Phát hiện địa chỉ nhận tiền thừa UTXO**

UTXO, hay **đầu ra giao dịch chưa được chi tiêu**, phải được chi tiêu toàn bộ trong một giao dịch. Nếu chỉ gửi một phần của UTXO đến địa chỉ khác, phần còn lại sẽ được gửi đến một địa chỉ nhận tiền thừa mới. Người quan sát có thể giả định địa chỉ mới này thuộc về người gửi, làm xâm phạm quyền riêng tư.

### Ví dụ

Để giảm thiểu rủi ro này, có thể dùng dịch vụ trộn tiền hoặc nhiều địa chỉ để che khuất quyền sở hữu.

## **Lộ thông tin trên mạng xã hội và diễn đàn**

Đôi khi người dùng chia sẻ địa chỉ Bitcoin của họ trên mạng, khiến việc **liên kết địa chỉ với chủ sở hữu trở nên dễ dàng**.

## **Phân tích đồ thị giao dịch**

Có thể trực quan hóa giao dịch dưới dạng đồ thị, từ đó phát hiện các kết nối tiềm năng giữa người dùng dựa trên luồng tiền.

## **Heuristic input không cần thiết (heuristic tiền thừa tối ưu)**

Heuristic này dựa trên việc phân tích các giao dịch có nhiều input và output để đoán output nào là tiền thừa được trả lại cho người gửi.

### Ví dụ

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Nếu việc thêm nhiều input khiến output tiền thừa lớn hơn bất kỳ input đơn lẻ nào, điều này có thể khiến heuristic bị nhầm lẫn.

## **Tái sử dụng địa chỉ cưỡng bức**

Kẻ tấn công có thể gửi những khoản tiền nhỏ đến các địa chỉ đã được sử dụng trước đó, với hy vọng người nhận sẽ gộp chúng với các input khác trong những giao dịch sau này, qua đó liên kết các địa chỉ với nhau.

### Hành vi đúng của ví

Ví nên tránh sử dụng các coin nhận được tại những địa chỉ đã dùng nhưng hiện không còn số dư để ngăn leak quyền riêng tư này.

## **Các kỹ thuật phân tích blockchain khác**

- **Số tiền thanh toán chính xác:** Các giao dịch không có tiền thừa thường là giao dịch giữa hai địa chỉ thuộc cùng một người dùng.
- **Số tiền tròn:** Số tiền tròn trong giao dịch gợi ý rằng đó là khoản thanh toán, còn output không tròn có thể là tiền thừa.
- **Fingerprinting ví:** Các ví khác nhau có kiểu tạo giao dịch riêng, cho phép nhà phân tích xác định phần mềm được sử dụng và có thể cả địa chỉ nhận tiền thừa.
- **Tương quan số tiền và thời gian:** Việc tiết lộ thời gian hoặc số tiền giao dịch có thể khiến các giao dịch bị truy vết.

## **Phân tích lưu lượng**

Bằng cách giám sát lưu lượng mạng, kẻ tấn công có thể liên kết các giao dịch hoặc block với địa chỉ IP, làm tổn hại quyền riêng tư của người dùng. Điều này đặc biệt đúng nếu một thực thể vận hành nhiều node Bitcoin, giúp họ tăng khả năng giám sát giao dịch.

## Thêm thông tin

Để xem danh sách đầy đủ các cuộc tấn công và biện pháp phòng thủ về quyền riêng tư, hãy truy cập [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Giao dịch Bitcoin ẩn danh

## Các cách nhận Bitcoin ẩn danh

- **Giao dịch tiền mặt**: Nhận bitcoin bằng tiền mặt.
- **Các lựa chọn thay thế tiền mặt**: Mua thẻ quà tặng rồi đổi chúng trực tuyến lấy bitcoin.
- **Đào coin**: Cách kiếm bitcoin riêng tư nhất là đào coin, đặc biệt là khi tự đào vì các mining pool có thể biết địa chỉ IP của thợ đào. [Thông tin về mining pool](https://en.bitcoin.it/wiki/Pooled_mining)
- **Trộm cắp**: Về lý thuyết, đánh cắp bitcoin cũng có thể là một cách nhận bitcoin ẩn danh, dù việc này là bất hợp pháp và không được khuyến khích.

## Dịch vụ trộn

Khi sử dụng dịch vụ trộn, người dùng có thể **gửi bitcoin** và nhận lại **những bitcoin khác**, khiến việc truy vết chủ sở hữu ban đầu trở nên khó khăn. Tuy nhiên, việc này đòi hỏi phải tin rằng dịch vụ sẽ không lưu log và thực sự trả lại bitcoin. Các lựa chọn trộn khác bao gồm sòng bạc Bitcoin.

## CoinJoin

**CoinJoin** gộp nhiều giao dịch từ những người dùng khác nhau thành một, khiến việc ghép input với output trở nên phức tạp hơn. Dù hiệu quả, các giao dịch có kích thước input và output độc nhất vẫn có thể bị truy vết.

Các giao dịch ví dụ có thể đã sử dụng CoinJoin gồm `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` và `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Để biết thêm thông tin, hãy truy cập [CoinJoin](https://coinjoin.io/en). Để tìm hiểu về một mixer smart contract Ethereum tách khoản tiền gửi khỏi các lần rút tiền sau đó, xem [Tornado Cash](https://tornado.cash).

## PayJoin

Là một biến thể của CoinJoin, **PayJoin** (hay P2EP) ngụy trang giao dịch giữa hai bên (ví dụ: khách hàng và người bán) thành một giao dịch thông thường, không có đặc điểm các output bằng nhau như CoinJoin. Điều này khiến việc phát hiện trở nên cực kỳ khó khăn và có thể vô hiệu hóa heuristic về quyền sở hữu chung input mà các đơn vị giám sát giao dịch sử dụng.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Các giao dịch như trên có thể là PayJoin, giúp tăng cường quyền riêng tư mà vẫn không thể phân biệt với các giao dịch bitcoin thông thường.

**Việc sử dụng PayJoin có thể làm gián đoạn đáng kể các phương pháp giám sát truyền thống**, khiến đây trở thành một bước tiến đầy hứa hẹn trong nỗ lực bảo vệ quyền riêng tư giao dịch.

# Các phương pháp tốt nhất để bảo vệ quyền riêng tư trong tiền mã hóa

## **Kỹ thuật đồng bộ hóa ví**

Để duy trì quyền riêng tư và bảo mật, việc đồng bộ hóa ví với blockchain là rất quan trọng. Có hai phương pháp nổi bật:

- **Full node**: Bằng cách tải xuống toàn bộ blockchain, full node đảm bảo mức độ riêng tư tối đa. Tất cả giao dịch từng được thực hiện đều được lưu trữ cục bộ, khiến đối thủ không thể xác định người dùng quan tâm đến giao dịch hoặc địa chỉ nào.
- **Lọc block phía client**: Phương pháp này tạo bộ lọc cho mọi block trong blockchain, cho phép ví nhận diện các giao dịch liên quan mà không tiết lộ mối quan tâm cụ thể cho những bên quan sát mạng. Ví nhẹ tải xuống các bộ lọc này và chỉ tải toàn bộ block khi tìm thấy kết quả khớp với địa chỉ của người dùng.

## **Sử dụng Tor để ẩn danh**

Vì Bitcoin hoạt động trên mạng ngang hàng, nên sử dụng Tor để che giấu địa chỉ IP, qua đó tăng cường quyền riêng tư khi tương tác với mạng.

## **Ngăn việc tái sử dụng địa chỉ**

Để bảo vệ quyền riêng tư, điều quan trọng là sử dụng địa chỉ mới cho mỗi giao dịch. Tái sử dụng địa chỉ có thể làm lộ quyền riêng tư bằng cách liên kết các giao dịch với cùng một thực thể. Các ví hiện đại được thiết kế để hạn chế việc tái sử dụng địa chỉ.

## **Chiến lược bảo vệ quyền riêng tư giao dịch**

- **Nhiều giao dịch**: Chia khoản thanh toán thành nhiều giao dịch có thể làm mờ số tiền giao dịch, ngăn chặn các cuộc tấn công xâm phạm quyền riêng tư.
- **Tránh tiền thừa**: Chọn giao dịch không cần đầu ra tiền thừa giúp tăng cường quyền riêng tư bằng cách phá vỡ các phương pháp phát hiện tiền thừa.
- **Nhiều đầu ra tiền thừa**: Nếu không thể tránh tiền thừa, tạo nhiều đầu ra tiền thừa vẫn có thể cải thiện quyền riêng tư.

# **Monero: Biểu tượng của tính ẩn danh**

Monero được thiết kế để ưu tiên quyền riêng tư giao dịch.

# **Ethereum: Gas và giao dịch**

## **Tìm hiểu về Gas**

Gas đo lường lượng tính toán cần thiết để thực thi các hoạt động trên Ethereum và được định giá bằng **gwei**. Ví dụ: một giao dịch có phí 2,310,000 gwei (hoặc 0.00231 ETH) có gas limit và phí cơ bản, cùng với phí ưu tiên để khuyến khích validator đưa giao dịch vào block. Người dùng có thể đặt phí tối đa để tránh trả quá mức; phần dư sẽ được hoàn lại.<sup>[[5]](#references)</sup>

## **Thực hiện giao dịch**

Giao dịch trên Ethereum gồm người gửi và người nhận, có thể là địa chỉ người dùng hoặc địa chỉ smart contract. Giao dịch cần có phí và phải được đưa vào một block. Thông tin thiết yếu trong giao dịch gồm người nhận, chữ ký của người gửi, giá trị, dữ liệu tùy chọn, gas limit và phí. Đáng chú ý, địa chỉ người gửi được suy ra từ chữ ký nên không cần có trong dữ liệu giao dịch.<sup>[[4]](#references)</sup>

Những phương pháp và cơ chế này là nền tảng cho bất kỳ ai muốn sử dụng tiền mã hóa, đồng thời ưu tiên quyền riêng tư và bảo mật.

## Red Teaming Web3 tập trung vào giá trị

- Kiểm kê các thành phần nắm giữ giá trị (signer, oracle, bridge, automation) để hiểu ai có thể chuyển tiền và bằng cách nào.
- Ánh xạ từng thành phần với các chiến thuật MITRE AADAPT liên quan để phát hiện các con đường leo thang đặc quyền.
- Diễn tập các chuỗi tấn công flash-loan/oracle/credential/xuyên chuỗi để xác thực tác động và ghi lại các điều kiện tiên quyết có thể bị khai thác.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Xâm phạm quy trình ký Web3

- Việc can thiệp chuỗi cung ứng của giao diện ví có thể sửa đổi payload EIP-712 ngay trước khi ký, thu thập chữ ký hợp lệ để chiếm quyền điều khiển proxy dựa trên delegatecall (ví dụ: ghi đè slot-0 của Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Trừu tượng hóa tài khoản (ERC-4337)

- Các lỗi phổ biến của smart account gồm bỏ qua kiểm soát truy cập `EntryPoint`, trường gas không có chữ ký, xác thực có trạng thái, phát lại ERC-1271 và rút cạn phí thông qua revert sau khi xác thực.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bảo mật smart contract

- Mutation testing để tìm điểm mù trong bộ kiểm thử:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Tính toàn vẹn của ZK Proof / zkVM Guest

Khi prover sử dụng **zkVM** hoặc mạch proof chuyên biệt cho ứng dụng để chứng thực một tuyên bố, verifier chỉ biết rằng **guest program đã thực thi đúng như được viết**. Nếu guest có **unsafe deserialization**, **undefined behavior** hoặc **thiếu các ràng buộc ngữ nghĩa**, prover độc hại có thể tạo proof được xác minh thành công trong khi **các chỉ số công khai hoặc bất biến được tuyên bố là sai**.<sup>[[7]](#references)</sup>

### Unsafe deserialization bên trong proof guest

- Coi các byte witness/circuit riêng tư là **đầu vào không đáng tin cậy do kẻ tấn công kiểm soát**, ngay cả khi chúng được proof che giấu.
- Tránh deserialize chúng bằng các helper không kiểm tra như `rkyv::access_unchecked`, trừ khi các byte đã được xác thực bên ngoài quy trình.
- Phải xác thực discriminant của enum, con trỏ tương đối, độ dài và chỉ mục được nạp từ dữ liệu đã serialize không đáng tin cậy trước khi chúng ảnh hưởng đến luồng điều khiển hoặc truy cập bộ nhớ.

Quy trình kiểm toán thực tế:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Nếu một trường như `op.kind` là enum và kẻ tấn công có thể chèn **discriminant nằm ngoài phạm vi**, thì mọi `match` phía sau trên giá trị đó đều đáng ngờ.

### Bypass bộ đếm bằng jump-table / UB

Nếu Rust biên dịch một `match` lớn thành **jump table**, discriminant enum không hợp lệ có thể dẫn đến **luồng điều khiển không xác định**. Một mẫu nguy hiểm là:<sup>[[7]](#references)[[9]](#references)</sup>

1. Một `match` cập nhật **các bộ đếm/ràng buộc trọng yếu về bảo mật**.
2. Một `match` thứ hai thực thi **ngữ nghĩa thực sự của lệnh**.
3. Discriminant nằm ngoài phạm vi truy cập vượt quá jump table thứ nhất và nhảy đến mã liên kết với jump table thứ hai.

Kết quả: thao tác vẫn được thực thi, nhưng đường xử lý ghi nhận bị bỏ qua. Trong zkVM, điều này có thể tạo ra proof giả báo cáo các chỉ số bất khả thi, chẳng hạn như ít gate hơn, ít thao tác tốn kém hơn hoặc các tài nguyên bị giới hạn khác bị làm sai lệch.

Danh sách kiểm tra:

- Tìm các enum do kẻ tấn công kiểm soát, được deserialize từ witness/đầu vào riêng tư.
- Kiểm tra các câu lệnh `match` lặp lại trên cùng một trường opcode/kind.
- Coi `unsafe` + deserialize không kiểm tra + dispatch opcode lớn là tổ hợp rủi ro cao.
- Khi cần, hãy reverse engineer binary đã được tạo; bố cục jump-table có thể quan trọng hơn mã nguồn.

### Thiếu ràng buộc ngữ nghĩa trong các trình thông dịch thuận nghịch/chuyên biệt

Đừng chỉ xác thực an toàn bộ nhớ; hãy xác thực cả **các quy tắc ngữ nghĩa** mà proof cần đảm bảo.

Với các tập lệnh thuận nghịch/tương tự lượng tử, hãy đảm bảo các toán hạng cần khác nhau được ràng buộc thực sự để chúng khác nhau. Một thao tác kiểu Toffoli/CCX được triển khai như sau:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

trở nên không an toàn nếu guest không từ chối:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Trong trường hợp đó, quá trình chuyển đổi thu gọn thành:

```text
q = q ^ (q & q) = 0
```

Điều này tạo ra một **primitive reset mang tính xác định**, phá vỡ các giả định về tính khả nghịch và cho phép thực hiện các phép tính không được dự định với chi phí thấp hơn. Trong các hệ thống proof xác thực mức sử dụng tài nguyên, điều này có thể giúp kẻ tấn công vượt qua các kiểm tra chức năng nhưng né tránh mô hình chi phí mà verifier tin rằng đang được áp dụng.

### Advice của prover bị ràng buộc chưa đầy đủ và số học mô-đun

Các giá trị được tải từ ngăn xếp advice/witness **do prover kiểm soát**, ngay cả khi chúng được mô tả là thương, số dư, nghịch đảo hoặc gợi ý đã tính trước. Một proof chỉ xác lập rằng witness thỏa mãn các ràng buộc đã triển khai; nó không xác lập phép tính dự định nếu các ràng buộc đó bỏ sót kiểm tra kiểu, phạm vi hoặc dạng chuẩn.<sup>[[13]](#references)</sup>

Đối với helper thực hiện phép rút gọn hoặc phép chia Euclid, hãy kiểm tra đầy đủ quan hệ số nguyên thay vì chỉ xem phép trừ hoặc phép nhân cuối cùng. Mọi limb của `q` và `r` phải được ràng buộc theo độ rộng đã khai báo, phép dựng lại `x = q * m + r` phải đúng trong biểu diễn số nguyên dự kiến, và phải áp dụng giới hạn chuẩn `0 <= r < m`. Hãy xác thực một giá trị **trước khi** truyền nó vào lệnh `u32`/`u64` có độ rộng nhỏ hơn; phép toán độ rộng nhỏ không thể chứng minh ngược rằng phần tử trường hoặc giá trị nhiều limb ban đầu có kiểu như mong đợi.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Lỗi `mod_12289` trong Miden minh họa kiểu khai thác này: thương số được kiểm tra dưới dạng giá trị 64-bit gồm hai limb, nhưng phần dư do advice cung cấp lại đi đến `u32overflowing_sub` mà không được xác thực tương đương. Prover độc hại có thể phối hợp các giá trị thương số/phần dư không hợp lệ để các ràng buộc phép trừ được triển khai vẫn thỏa mãn, trong khi thủ tục trả về phần dư không đúng theo toán học. Vì kết quả này được dùng trong quá trình xác minh Falcon, lỗi soundness có thể bị khai thác thành chữ ký ủy quyền giả mạo, chứ không chỉ tạo ra kết quả số học sai.<sup>[[13]](#references)</sup>

### Kiểm tra VM mật mã dùng stack ngầm

Ngôn ngữ stack che giấu toán hạng, vì vậy trước tiên hãy chuyển các lệnh sang IR, trong đó mỗi giá trị stack được tiêu thụ hoặc tạo ra là một biểu thức có nguồn gốc. Sau đó, quy trình phân tích thận trọng có thể:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Xây dựng call graph và suy luận hiệu ứng stack đầu vào/đầu ra của thủ tục.
2. Thực thi tượng trưng các lệnh được hỗ trợ và chuyển luồng điều khiển thành biểu thức SSA/có cấu trúc.
3. Lan truyền các sự kiện trừu tượng như `Unknown`, `ProvenU32`, `Bool`, nguồn gốc giá trị và trạng thái khởi tạo cục bộ cho đến khi đạt điểm bất động.
4. Đánh dấu các giá trị bắt nguồn từ advice đi đến phép toán số học có kiểu hoặc sink yêu cầu giá trị khác không mà không qua bước làm sạch trên **mọi** đường đi đầu vào.
5. So sánh chữ ký được khai báo với chữ ký suy luận được và xác minh rằng mọi lối thoát đều bảo toàn các giá trị stack thuộc về caller.

Hãy xem chữ ký không xác định hoặc cấu trúc không được hỗ trợ là **khoảng trống phân tích**, không phải kết quả an toàn. Lời gọi động, vòng lặp không trung hòa stack và các nhánh có hiệu ứng stack khác nhau có thể khiến việc theo dõi slot stack một cách sound trở nên bất khả thi; decompiler an toàn hơn sẽ từ chối hoặc đánh dấu các trường hợp này thay vì tạo ra pseudocode có vẻ hợp lý nhưng sai.<sup>[[10]](#references)[[13]](#references)</sup>

Tại các điểm hợp nhất luồng điều khiển, chỉ giữ lại một thuộc tính nếu thuộc tính đó đúng trên mọi nhánh tiền nhiệm (ví dụ: `ProvenU32 join Unknown = Unknown`). Đồng thời, cần phân biệt hội tụ điểm bất động với việc chạm giới hạn số vòng lặp: chỉ một phép xấp xỉ trên sound đã hội tụ mới có thể biện minh cho việc xem không có cảnh báo là bằng chứng rằng mọi thực thi được biểu diễn đều thỏa mãn thuộc tính đó.<sup>[[11]](#references)</sup>

### Dùng nghĩa vụ chứng minh để làm lộ các điều kiện tiên quyết ẩn

Với tập lệnh nhỏ, hãy chuyển thủ tục thành mô hình VM hình thức có thể thực thi và chứng minh cả kết quả lẫn toàn bộ phép biến đổi stack. Định lý cần bao quát tính kết thúc, đầu vào có kiểu, tiền tố đầu ra mong đợi và việc bảo toàn stack caller không bị chạm đến. Hãy kiểm tra phát biểu định lý cẩn thận như kiểm tra chứng minh: kernel có thể xác thực chứng minh cho một mệnh đề vô tình bị làm yếu đi.<sup>[[12]](#references)[[13]](#references)</sup>

Các giả thiết bất ngờ là phát hiện hữu ích. Trong quá trình đánh giá Miden, một chứng minh về phép xoay phải 64-bit yêu cầu `shift mod 32 != 0`, qua đó làm lộ một trường hợp biên lỗi với đầu vào lớn khi shift là bội số của 32; một chứng minh khác phát hiện `wrapping_mul` 256-bit loại bỏ các giá trị stack thuộc về caller. Hãy thêm trường hợp biên đã phát hiện vào các bài kiểm thử, sau đó sửa phần triển khai hoặc chủ động siết chặt điều kiện tiên quyết công khai thay vì âm thầm chấp nhận giả định bổ sung.<sup>[[12]](#references)[[13]](#references)</sup>

### Cần kiểm thử gì trong hệ thống ZK

- Fuzz mọi parser phía guest bằng các encoding witness/đầu vào riêng tư sai định dạng.
- Xác nhận enum được kiểm tra phạm vi trước khi dispatch opcode.
- Bổ sung kiểm tra ngữ nghĩa cho việc alias toán hạng và các dạng lệnh không hợp lệ khác.
- Truy vết mọi nguồn advice/witness đến từng sink số học có kiểu và yêu cầu xác thực trên mọi đường đi.<sup>[[11]](#references)[[13]](#references)</sup>
- Kiểm thử các helper số học với limb không chuẩn tắc, phần dư ngoài phạm vi và số lượng shift ở các giá trị biên.<sup>[[12]](#references)[[13]](#references)</sup>
- Xác nhận chiều cao stack và việc bảo toàn các giá trị nằm dưới các đối số được khai báo của thủ tục trên mọi lần trả về.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- So sánh các bộ đếm được báo cáo/công khai với một bản triển khai tham chiếu độc lập.
- Hãy nhớ rằng proof hợp lệ vẫn có thể chứng minh **mệnh đề sai** nếu chương trình guest có lỗi.

## Ủy quyền phụ thuộc trạng thái

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Khai thác DeFi/AMM

Nếu bạn đang nghiên cứu khai thác thực tế trên DEX và AMM (hook Uniswap v4, lạm dụng làm tròn/độ chính xác, swap vượt ngưỡng được khuếch đại bằng flash loan), hãy xem:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Với các pool có trọng số nhiều tài sản, lưu cache số dư ảo và có thể bị đầu độc khi `supply == 0`, hãy tìm hiểu:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Bằng chứng cổ phần - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Giải thích về khóa công khai và khóa riêng tư - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Giao dịch đa chữ ký là gì? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Giao dịch | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas và phí | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Quyền riêng tư - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Chúng tôi đã đánh bại proof zero-knowledge về mật mã phân tích lượng tử của Google](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Bảo vệ tiền mã hóa đường cong elliptic trước các lỗ hổng lượng tử: Ước tính tài nguyên và biện pháp giảm thiểu (bản đã vá)](https://arxiv.org/abs/2603.28846v2)
- [9] [Kho proof-of-concept của Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Kiến trúc decompiler MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Công cụ phân tích tĩnh MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Mô hình MASM-to-Lean và các chứng minh tính đúng đắn](https://github.com/trailofbits/masm-lean)
- [13] [Đánh giá bảo mật trong thời đại AI (đủ tốt)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
