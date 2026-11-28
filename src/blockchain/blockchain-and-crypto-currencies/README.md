# Blockchain và tiền mã hóa

{{#include ../../banners/hacktricks-training.md}}

Chương này trình bày các khái niệm về blockchain và bảo mật on-chain. Nếu gặp một Bitcoin peer đang bị lộ, hãy bắt đầu với [liệt kê dịch vụ Bitcoin P2P](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); với giao diện frontend trên trình duyệt, kết nối ví hoặc backend off-chain, hãy dùng [pentesting DApp](../../pentesting-web/dapps-DecentralizedApplications.md). Để tìm hiểu các hoạt động bảo vệ quyền riêng tư trong tiền mã hóa và những giới hạn của chúng, hãy xem [chương về quyền riêng tư trong tiền mã hóa](../../privacy/cryptocurrency-privacy.md).

## Các khái niệm cơ bản

- **Smart Contracts** được định nghĩa là các chương trình thực thi trên blockchain khi đáp ứng một số điều kiện nhất định, tự động hóa việc thực hiện thỏa thuận mà không cần bên trung gian.
- **Decentralized Applications (dApps)** được xây dựng dựa trên smart contracts, có giao diện frontend thân thiện với người dùng và backend minh bạch, có thể kiểm tra.
- **Tokens & Coins** khác nhau ở chỗ coin đóng vai trò như tiền kỹ thuật số, còn token đại diện cho giá trị hoặc quyền sở hữu trong những bối cảnh cụ thể.
  - **Utility Tokens** cấp quyền truy cập dịch vụ, còn **Security Tokens** biểu thị quyền sở hữu tài sản.
- **DeFi** là viết tắt của Decentralized Finance, cung cấp các dịch vụ tài chính mà không cần cơ quan trung ương.
- **DEX** và **DAOs** lần lượt chỉ các nền tảng sàn giao dịch phi tập trung và các tổ chức tự trị phi tập trung.

Để tìm hiểu các thuật ngữ về lệnh giao ngay, futures, đòn bẩy và quyền chọn thường dùng trên thị trường tiền mã hóa, hãy xem [Các thuật ngữ đầu tư](investment-terms.md). Để tìm hiểu cách khai thác tỷ lệ funding trong các giao thức perpetual, hãy xem [Khai thác tỷ lệ funding của Perpetual](perpetual-funding-rate-exploitation.md).

## Cơ chế đồng thuận

Cơ chế đồng thuận đảm bảo các giao dịch được xác thực một cách an toàn và thống nhất trên blockchain:

- **Proof of Work (PoW)** dựa vào năng lực tính toán để xác minh giao dịch.
- **Proof of Stake (PoS)** yêu cầu validator nắm giữ một lượng token nhất định, giúp giảm mức tiêu thụ năng lượng so với PoW.<sup>[[1]](#references)</sup>

## Những điều cơ bản về Bitcoin

### Giao dịch

Giao dịch Bitcoin bao gồm việc chuyển tiền giữa các địa chỉ. Giao dịch được xác thực bằng chữ ký số, đảm bảo chỉ chủ sở hữu khóa riêng mới có thể khởi tạo giao dịch chuyển tiền.<sup>[[2]](#references)</sup>

#### Các thành phần chính:

- **Giao dịch đa chữ ký** yêu cầu nhiều chữ ký để xác thực một giao dịch.<sup>[[3]](#references)</sup>
- Giao dịch gồm **đầu vào** (nguồn tiền), **đầu ra** (đích đến), **phí** (trả cho thợ đào) và **script** (các quy tắc giao dịch).

### Lightning Network

Lightning Network hướng đến cải thiện khả năng mở rộng của Bitcoin bằng cách cho phép thực hiện nhiều giao dịch trong một kênh và chỉ phát trạng thái cuối cùng lên blockchain.

## Các vấn đề về quyền riêng tư của Bitcoin

Các cuộc tấn công quyền riêng tư như **Common Input Ownership** và **phát hiện địa chỉ tiền thừa UTXO** khai thác các mẫu giao dịch. Những chiến lược như **Mixers** và **CoinJoin** cải thiện tính ẩn danh bằng cách che khuất liên kết giao dịch giữa người dùng.

## Mua Bitcoin ẩn danh

Các phương thức bao gồm giao dịch tiền mặt, đào coin và sử dụng mixers. **CoinJoin** trộn nhiều giao dịch để khiến việc truy vết phức tạp hơn, trong khi **PayJoin** ngụy trang CoinJoin thành các giao dịch thông thường để tăng cường quyền riêng tư.

# Tóm tắt các cuộc tấn công vào quyền riêng tư Bitcoin

Trong thế giới Bitcoin, quyền riêng tư của giao dịch và tính ẩn danh của người dùng thường là những vấn đề đáng quan tâm. Dưới đây là phần tổng quan đơn giản về một số phương thức phổ biến mà kẻ tấn công có thể dùng để xâm phạm quyền riêng tư của Bitcoin.<sup>[[6]](#references)</sup>

## **Giả định quyền sở hữu chung đầu vào**

Thông thường, việc kết hợp đầu vào từ nhiều người dùng trong một giao dịch là hiếm gặp do tính phức tạp của nó. Vì vậy, **người ta thường giả định rằng hai địa chỉ đầu vào trong cùng một giao dịch thuộc về cùng một chủ sở hữu**.

## **Phát hiện địa chỉ tiền thừa UTXO**

UTXO, hay **đầu ra giao dịch chưa được chi tiêu**, phải được chi tiêu toàn bộ trong một giao dịch. Nếu chỉ một phần được gửi đến địa chỉ khác, phần còn lại sẽ được chuyển đến một địa chỉ tiền thừa mới. Người quan sát có thể giả định địa chỉ mới này thuộc về người gửi, từ đó xâm phạm quyền riêng tư.

### Ví dụ

Để giảm thiểu rủi ro này, có thể dùng dịch vụ trộn tiền hoặc sử dụng nhiều địa chỉ để che khuất quyền sở hữu.

## **Lộ thông tin trên mạng xã hội và diễn đàn**

Đôi khi người dùng chia sẻ địa chỉ Bitcoin của họ trên mạng, khiến việc **liên kết địa chỉ với chủ sở hữu trở nên dễ dàng**.

## **Phân tích đồ thị giao dịch**

Có thể biểu diễn giao dịch dưới dạng đồ thị, qua đó làm lộ các mối liên hệ tiềm tàng giữa người dùng dựa trên luồng tiền.

## **Heuristic đầu vào không cần thiết (Heuristic tiền thừa tối ưu)**

Heuristic này dựa trên việc phân tích các giao dịch có nhiều đầu vào và đầu ra để phỏng đoán đầu ra nào là tiền thừa được gửi lại cho người gửi.

### Ví dụ

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Nếu việc thêm nhiều input khiến change output lớn hơn bất kỳ input đơn lẻ nào, điều này có thể đánh lừa heuristic.

## **Tái sử dụng địa chỉ bắt buộc**

Kẻ tấn công có thể gửi những khoản nhỏ đến các địa chỉ đã dùng trước đó, với hy vọng người nhận sẽ kết hợp chúng với các input khác trong những giao dịch tương lai, từ đó liên kết các địa chỉ với nhau.

### Hành vi đúng của ví

Ví nên tránh sử dụng các coin nhận được tại những địa chỉ đã dùng và hiện không còn số dư, nhằm ngăn chặn privacy leak này.

## **Các kỹ thuật phân tích blockchain khác**

- **Số tiền thanh toán chính xác:** Các giao dịch không có tiền thừa nhiều khả năng là giao dịch giữa hai địa chỉ thuộc cùng một người dùng.
- **Số tiền tròn:** Số tiền tròn trong giao dịch cho thấy đó có thể là khoản thanh toán; output không tròn nhiều khả năng là tiền thừa.
- **Fingerprinting ví:** Các ví khác nhau có những mẫu tạo giao dịch riêng, cho phép nhà phân tích xác định phần mềm được sử dụng và có khả năng nhận diện địa chỉ nhận tiền thừa.
- **Tương quan số tiền và thời gian:** Việc tiết lộ thời gian hoặc số tiền giao dịch có thể khiến các giao dịch bị truy vết.

## **Phân tích lưu lượng**

Bằng cách giám sát lưu lượng mạng, kẻ tấn công có thể liên kết giao dịch hoặc block với địa chỉ IP, làm tổn hại quyền riêng tư của người dùng. Điều này đặc biệt đúng nếu một thực thể vận hành nhiều node Bitcoin, giúp họ tăng khả năng giám sát giao dịch.

## Thêm thông tin

Để xem danh sách toàn diện về các cuộc tấn công và biện pháp phòng vệ quyền riêng tư, hãy truy cập [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Giao dịch Bitcoin ẩn danh

## Các cách nhận Bitcoin ẩn danh

- **Giao dịch tiền mặt**: Nhận bitcoin bằng tiền mặt.
- **Các lựa chọn thay thế tiền mặt**: Mua thẻ quà tặng rồi đổi chúng trực tuyến lấy bitcoin.
- **Đào coin**: Cách riêng tư nhất để kiếm bitcoin là đào coin, đặc biệt khi đào một mình vì các mining pool có thể biết địa chỉ IP của thợ đào. [Thông tin về Mining Pool](https://en.bitcoin.it/wiki/Pooled_mining)
- **Trộm cắp**: Về mặt lý thuyết, đánh cắp bitcoin cũng có thể là một cách nhận bitcoin ẩn danh, dù việc này là bất hợp pháp và không được khuyến khích.

## Dịch vụ trộn

Khi sử dụng dịch vụ trộn, người dùng có thể **gửi bitcoin** và nhận lại **những bitcoin khác**, khiến việc truy tìm chủ sở hữu ban đầu trở nên khó khăn. Tuy nhiên, cách này đòi hỏi phải tin tưởng dịch vụ sẽ không lưu log và thực sự trả lại bitcoin. Các lựa chọn trộn khác bao gồm sòng bạc Bitcoin.

## CoinJoin

**CoinJoin** gộp nhiều giao dịch từ những người dùng khác nhau thành một, khiến việc ghép input với output trở nên phức tạp hơn. Dù hiệu quả, các giao dịch có kích thước input và output riêng biệt vẫn có thể bị truy vết.

Các giao dịch ví dụ có thể đã sử dụng CoinJoin gồm `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` và `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Để biết thêm thông tin, hãy truy cập [CoinJoin](https://coinjoin.io/en). Để xem một mixer dùng smart contract trên Ethereum, tách các khoản tiền gửi khỏi những lần rút tiền sau đó, hãy xem [Tornado Cash](https://tornado.cash).

## PayJoin

Là một biến thể của CoinJoin, **PayJoin** (hay P2EP) ngụy trang giao dịch giữa hai bên (ví dụ: khách hàng và người bán) thành một giao dịch thông thường, không có đặc điểm output bằng nhau vốn đặc trưng cho CoinJoin. Điều này khiến giao dịch cực kỳ khó bị phát hiện và có thể làm mất hiệu lực heuristic về quyền sở hữu chung input mà các đơn vị giám sát giao dịch sử dụng.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Các giao dịch như trên có thể là PayJoin, giúp tăng cường quyền riêng tư mà vẫn không thể phân biệt với các giao dịch bitcoin tiêu chuẩn.

**Việc sử dụng PayJoin có thể gây gián đoạn đáng kể cho các phương pháp giám sát truyền thống**, khiến đây trở thành một bước phát triển đầy hứa hẹn trong nỗ lực bảo vệ quyền riêng tư của giao dịch.

# Các phương pháp tốt nhất để bảo vệ quyền riêng tư trong tiền mã hóa

## **Kỹ thuật đồng bộ hóa ví**

Để duy trì quyền riêng tư và bảo mật, việc đồng bộ hóa ví với blockchain là rất quan trọng. Có hai phương pháp nổi bật:

- **Full node**: Bằng cách tải xuống toàn bộ blockchain, full node đảm bảo mức độ riêng tư tối đa. Tất cả giao dịch từng được thực hiện đều được lưu trữ cục bộ, khiến đối phương không thể xác định người dùng quan tâm đến giao dịch hoặc địa chỉ nào.
- **Lọc khối phía máy khách**: Phương pháp này tạo bộ lọc cho từng khối trong blockchain, cho phép ví xác định các giao dịch liên quan mà không tiết lộ mối quan tâm cụ thể cho những bên quan sát mạng. Ví nhẹ tải xuống các bộ lọc này và chỉ tải toàn bộ khối khi tìm thấy kết quả khớp với địa chỉ của người dùng.

## **Sử dụng Tor để ẩn danh**

Vì Bitcoin hoạt động trên mạng ngang hàng, nên bạn nên sử dụng Tor để che giấu địa chỉ IP, qua đó tăng cường quyền riêng tư khi tương tác với mạng.

## **Ngăn việc tái sử dụng địa chỉ**

Để bảo vệ quyền riêng tư, điều quan trọng là sử dụng địa chỉ mới cho mỗi giao dịch. Tái sử dụng địa chỉ có thể làm tổn hại quyền riêng tư bằng cách liên kết các giao dịch với cùng một thực thể. Các ví hiện đại được thiết kế để ngăn người dùng tái sử dụng địa chỉ.

## **Chiến lược bảo vệ quyền riêng tư của giao dịch**

- **Nhiều giao dịch**: Chia khoản thanh toán thành nhiều giao dịch có thể che khuất số tiền giao dịch, ngăn chặn các cuộc tấn công xâm phạm quyền riêng tư.
- **Tránh tiền thừa**: Chọn các giao dịch không cần đầu ra tiền thừa giúp tăng cường quyền riêng tư bằng cách làm gián đoạn các phương pháp phát hiện tiền thừa.
- **Nhiều đầu ra tiền thừa**: Nếu không thể tránh tiền thừa, việc tạo nhiều đầu ra tiền thừa vẫn có thể cải thiện quyền riêng tư.

# **Monero: Biểu tượng của tính ẩn danh**

Monero được thiết kế để ưu tiên quyền riêng tư của giao dịch.

# **Ethereum: Gas và giao dịch**

## **Tìm hiểu về Gas**

Gas đo lường lượng tính toán cần thiết để thực thi các thao tác trên Ethereum và được định giá bằng **gwei**. Ví dụ: một giao dịch có giá 2,310,000 gwei (hay 0.00231 ETH) có giới hạn gas và phí cơ sở, cùng với phí ưu tiên để khuyến khích validator đưa giao dịch vào khối. Người dùng có thể đặt mức phí tối đa để đảm bảo không trả quá nhiều; phần dư sẽ được hoàn lại.<sup>[[5]](#references)</sup>

## **Thực hiện giao dịch**

Giao dịch trên Ethereum có người gửi và người nhận, có thể là địa chỉ người dùng hoặc địa chỉ smart contract. Giao dịch cần có phí và phải được đưa vào một khối. Thông tin thiết yếu trong giao dịch gồm người nhận, chữ ký của người gửi, giá trị, dữ liệu tùy chọn, giới hạn gas và phí. Đáng chú ý, địa chỉ người gửi được suy ra từ chữ ký, nên không cần có địa chỉ này trong dữ liệu giao dịch.<sup>[[4]](#references)</sup>

Các phương pháp và cơ chế này là nền tảng cho bất kỳ ai muốn tham gia vào lĩnh vực tiền mã hóa, đồng thời ưu tiên quyền riêng tư và bảo mật.

## Red Teaming Web3 tập trung vào giá trị

- Kiểm kê các thành phần nắm giữ giá trị (signer, oracle, bridge, tự động hóa) để hiểu ai có thể chuyển tiền và bằng cách nào.
- Ánh xạ từng thành phần với các chiến thuật MITRE AADAPT liên quan để phát hiện các đường dẫn leo thang đặc quyền.
- Diễn tập các chuỗi tấn công flash-loan/oracle/credential/xuyên chuỗi để xác thực tác động và ghi lại các điều kiện tiên quyết có thể khai thác.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Xâm phạm quy trình ký Web3

- Việc can thiệp chuỗi cung ứng của giao diện ví có thể sửa đổi payload EIP-712 ngay trước khi ký, thu thập chữ ký hợp lệ để chiếm quyền điều khiển proxy dựa trên delegatecall (ví dụ: ghi đè slot-0 của Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Trừu tượng hóa tài khoản (ERC-4337)

- Các lỗi phổ biến của smart account bao gồm vượt qua kiểm soát truy cập `EntryPoint`, các trường gas không được ký, xác thực có trạng thái, phát lại ERC-1271 và rút cạn phí thông qua việc revert sau khi xác thực.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bảo mật smart contract

- Mutation testing để tìm các điểm mù trong bộ kiểm thử:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Tính toàn vẹn của zk proof / zkVM guest

Khi prover sử dụng **zkVM** hoặc một proof circuit dành riêng cho ứng dụng để chứng thực một tuyên bố, verifier chỉ biết rằng **guest program đã thực thi đúng như được viết**. Nếu guest có **unsafe deserialization**, **undefined behavior** hoặc **thiếu các ràng buộc ngữ nghĩa**, prover độc hại có thể tạo ra proof được xác minh thành công trong khi **các chỉ số công khai hoặc invariant được tuyên bố là sai**.<sup>[[7]](#references)</sup>

### Unsafe deserialization bên trong proof guest

- Hãy xem các byte của private witness/circuit là **đầu vào không đáng tin cậy do attacker cung cấp**, ngay cả khi chúng bị ẩn bởi proof.
- Tránh deserialize chúng bằng các helper không kiểm tra như `rkyv::access_unchecked`, trừ khi các byte đã được xác thực qua một kênh riêng.
- Phải xác thực enum discriminant, con trỏ tương đối, độ dài và chỉ mục được tải từ dữ liệu đã serialize không đáng tin cậy trước khi chúng ảnh hưởng đến luồng điều khiển hoặc truy cập bộ nhớ.

Phương pháp audit thực tế:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Nếu một trường như `op.kind` là enum và kẻ tấn công có thể chèn **discriminant ngoài phạm vi**, mọi `match` phía sau trên giá trị đó đều đáng ngờ.

### Vượt qua bộ đếm bằng jump-table / UB

Nếu Rust biên dịch một `match` lớn thành **jump table**, discriminant enum không hợp lệ có thể dẫn đến **luồng điều khiển không xác định**. Một mẫu nguy hiểm là:<sup>[[7]](#references)[[9]](#references)</sup>

1. Một `match` cập nhật **các bộ đếm/ràng buộc quan trọng về bảo mật**.
2. Một `match` thứ hai thực hiện **ngữ nghĩa lệnh thực sự**.
3. Discriminant ngoài phạm vi truy cập vượt quá jump table thứ nhất và nhảy đến mã liên quan đến jump table thứ hai.

Kết quả: thao tác vẫn được thực thi, nhưng đường đi cập nhật số liệu bị bỏ qua. Trong zkVM, điều này có thể tạo ra bằng chứng giả báo cáo các chỉ số bất khả thi như số gate ít hơn, số thao tác tốn kém ít hơn hoặc các tài nguyên bị giới hạn khác bị làm sai lệch.

Danh sách kiểm tra:

- Tìm các enum do kẻ tấn công kiểm soát được deserialize từ witness/private input.
- Kiểm tra các câu lệnh `match` lặp lại trên cùng trường opcode/kind.
- Xem tổ hợp `unsafe` + deserialize không kiểm tra + dispatch opcode lớn là rủi ro cao.
- Khi cần, dịch ngược binary đã phát ra; bố cục jump table có thể quan trọng hơn mã nguồn.

### Thiếu ràng buộc ngữ nghĩa trong interpreter thuận nghịch/chuyên biệt

Đừng chỉ kiểm tra an toàn bộ nhớ; hãy kiểm tra cả **các quy tắc ngữ nghĩa** mà bằng chứng cần thực thi.

Với các tập lệnh kiểu thuận nghịch/lượng tử, hãy đảm bảo các toán hạng cần phân biệt thực sự bị ràng buộc phải khác nhau. Một thao tác kiểu Toffoli/CCX được triển khai như sau:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

trở nên không an toàn nếu guest không từ chối:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Trong trường hợp đó, quá trình chuyển đổi được rút gọn thành:

```text
q = q ^ (q & q) = 0
```

Điều này tạo ra một **primitive đặt lại mang tính xác định**, phá vỡ các giả định về tính thuận nghịch và cho phép thực hiện các phép tính ngoài ý muốn với chi phí thấp hơn. Trong các hệ thống chứng minh xác thực việc sử dụng tài nguyên, điều này có thể giúp kẻ tấn công vượt qua các kiểm tra chức năng nhưng né tránh mô hình chi phí mà verifier cho rằng đang được thực thi.

### Advice của prover không bị ràng buộc đầy đủ và số học modulo

Các giá trị được tải từ **ngăn xếp advice/witness do prover kiểm soát**, ngay cả khi chúng được mô tả là thương, số dư, nghịch đảo hoặc gợi ý đã tính trước. Một proof chỉ xác lập rằng witness thỏa mãn các ràng buộc được triển khai; nó không xác lập rằng phép tính dự định đã được thực hiện nếu các ràng buộc đó bỏ qua việc kiểm tra kiểu, phạm vi hoặc dạng chuẩn.<sup>[[13]](#references)</sup>

Đối với một hàm hỗ trợ phép rút gọn hoặc phép chia Euclid, hãy kiểm tra toàn bộ quan hệ số nguyên, thay vì chỉ kiểm tra phép trừ hoặc phép nhân cuối cùng. Mọi limb của `q` và `r` phải được ràng buộc trong độ rộng đã khai báo; phép dựng lại `x = q * m + r` phải đúng trong biểu diễn số nguyên dự định; và phải thực thi giới hạn chuẩn tắc `0 <= r < m`. Hãy xác thực một giá trị **trước khi** truyền nó cho một lệnh `u32`/`u64` hẹp hơn; phép toán hẹp không thể chứng minh hồi tố rằng phần tử trường hoặc giá trị nhiều limb ban đầu có kiểu mong đợi.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Lỗi `mod_12289` trong Miden minh họa mô thức khai thác: thương được kiểm tra dưới dạng giá trị 64 bit gồm hai limb, nhưng số dư do advice cung cấp lại được đưa vào `u32overflowing_sub` mà không có bước xác thực tương đương. Prover độc hại có thể phối hợp các giá trị thương/số dư không hợp lệ để các ràng buộc phép trừ được triển khai vẫn thỏa mãn, trong khi thủ tục trả về một số dư không đúng về mặt toán học. Vì kết quả này được dùng trong quá trình xác minh Falcon, lỗi soundness có thể bị nâng cấp thành chữ ký ủy quyền giả mạo, thay vì chỉ tạo ra kết quả số học sai.<sup>[[13]](#references)</sup>

### Kiểm tra các VM mật mã có stack ẩn

Ngôn ngữ stack ẩn các toán hạng, vì vậy trước tiên hãy nâng các lệnh lên IR, trong đó mỗi giá trị stack được tiêu thụ và tạo ra là một biểu thức có provenance. Sau đó, một pipeline phân tích thận trọng có thể:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Xây dựng call graph và suy luận hiệu ứng đầu vào/đầu ra của stack cho các procedure.
2. Thực thi tượng trưng các lệnh được hỗ trợ và nâng luồng điều khiển thành các biểu thức SSA/có cấu trúc.
3. Lan truyền các sự kiện trừu tượng như `Unknown`, `ProvenU32`, `Bool`, provenance của giá trị và trạng thái khởi tạo cục bộ cho đến khi đạt fixed point.
4. Đánh dấu các giá trị bắt nguồn từ advice đi đến phép toán có kiểu hoặc sink yêu cầu giá trị khác 0 mà không qua sanitizer trên **mọi** đường đi đầu vào.
5. So sánh chữ ký được khai báo với chữ ký suy luận được và xác minh rằng mọi lối thoát đều giữ nguyên các giá trị stack thuộc về caller.

Hãy xem chữ ký không xác định hoặc cấu trúc không được hỗ trợ là một **khoảng trống phân tích**, không phải kết quả sạch. Lệnh gọi động, vòng lặp không trung hòa stack và các nhánh có hiệu ứng stack khác nhau có thể khiến việc theo dõi chính xác các stack slot trở nên bất khả thi; decompiler an toàn hơn sẽ từ chối hoặc đánh dấu những trường hợp này thay vì xuất ra pseudocode có vẻ hợp lý nhưng sai.<sup>[[10]](#references)[[13]](#references)</sup>

Tại các điểm hợp nhất luồng điều khiển, chỉ giữ lại một thuộc tính nếu nó đúng trên mọi nhánh tiền nhiệm (ví dụ: `ProvenU32 join Unknown = Unknown`). Đồng thời, phân biệt hội tụ fixed point với việc chạm giới hạn số vòng lặp: chỉ một phép xấp xỉ trên bao hội tụ và sound mới có thể biện minh cho việc xem sự vắng mặt của cảnh báo là bằng chứng rằng mọi thực thi được mô hình hóa đều thỏa mãn thuộc tính đó.<sup>[[11]](#references)</sup>

### Dùng nghĩa vụ chứng minh để làm lộ các tiền điều kiện ẩn

Với các tập lệnh nhỏ, hãy chuyển procedure thành mô hình VM hình thức có thể thực thi và chứng minh cả kết quả lẫn toàn bộ phép biến đổi stack. Định lý cần bao quát tính kết thúc, đầu vào có kiểu, tiền tố đầu ra mong đợi và việc bảo toàn stack caller không bị tác động. Hãy kiểm tra phát biểu định lý cẩn thận như khi kiểm tra chứng minh: kernel có thể xác thực một chứng minh cho một mệnh đề vô tình bị làm yếu đi.<sup>[[12]](#references)[[13]](#references)</sup>

Các giả thuyết bất ngờ là những phát hiện hữu ích. Trong đợt review Miden, chứng minh cho phép xoay phải 64 bit yêu cầu `shift mod 32 != 0`, qua đó làm lộ một trường hợp biên gây lỗi với đầu vào lớn khi shift là bội số của 32; một chứng minh khác phát hiện `wrapping_mul` 256 bit làm mất các giá trị stack thuộc về caller. Hãy thêm trường hợp biên được phát hiện vào test, rồi sửa implementation hoặc chủ động siết chặt tiền điều kiện công khai, thay vì âm thầm chấp nhận giả định bổ sung đó.<sup>[[12]](#references)[[13]](#references)</sup>

### Cần kiểm thử gì trong hệ thống ZK

- Fuzz tất cả parser phía guest với các mã hóa witness/private input sai định dạng.
- Xác nhận enum nằm trong phạm vi hợp lệ trước khi dispatch opcode.
- Bổ sung kiểm tra ngữ nghĩa cho việc alias toán hạng và các dạng lệnh không hợp lệ khác.
- Truy vết mọi nguồn advice/witness đến từng sink số học có kiểu và yêu cầu xác thực trên mọi đường đi.<sup>[[11]](#references)[[13]](#references)</sup>
- Kiểm thử các helper số học với limb không canonical, số dư ngoài phạm vi và số lần dịch biên.<sup>[[12]](#references)[[13]](#references)</sup>
- Xác nhận chiều cao stack và việc bảo toàn các giá trị bên dưới các đối số được khai báo của procedure trên mọi lần trả về.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- So sánh các bộ đếm được báo cáo/công khai với một implementation tham chiếu độc lập.
- Hãy nhớ rằng một proof hợp lệ vẫn có thể chứng minh **mệnh đề sai** nếu chương trình guest có lỗi.

## Ủy quyền phụ thuộc trạng thái

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Khai thác DeFi/AMM

Nếu bạn đang nghiên cứu việc khai thác thực tế trên DEX và AMM (hook Uniswap v4, lạm dụng làm tròn/độ chính xác, các giao dịch swap vượt ngưỡng được khuếch đại bằng flash-loan), hãy xem:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Với các pool weighted đa tài sản cache số dư ảo và có thể bị đầu độc khi `supply == 0`, hãy xem:

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
- [7] [Trail of Bits - Chúng tôi đã đánh bại bằng chứng zero-knowledge về phân tích mật mã lượng tử của Google](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Bảo vệ tiền mã hóa đường cong elliptic trước các lỗ hổng lượng tử: Ước tính tài nguyên và biện pháp giảm thiểu (bản đã vá)](https://arxiv.org/abs/2603.28846v2)
- [9] [Kho lưu trữ proof-of-concept của Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Kiến trúc decompiler MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Engine phân tích tĩnh MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Mô hình MASM-to-Lean và các chứng minh tính đúng đắn](https://github.com/trailofbits/masm-lean)
- [13] [Kiểm tra bảo mật trong thời đại AI (đủ tốt)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
