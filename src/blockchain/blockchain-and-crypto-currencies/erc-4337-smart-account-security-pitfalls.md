# Những cạm bẫy bảo mật của Smart Account ERC-4337

{{#include ../../banners/hacktricks-training.md}}

Account abstraction của ERC-4337 biến ví thành các hệ thống có thể lập trình. Luồng cốt lõi là **validate-then-execute** trên toàn bộ một gói: `EntryPoint` xác thực mọi `UserOperation` trước khi thực thi bất kỳ thao tác nào.<sup>[[5]](#references)</sup> Trình tự này tạo ra bề mặt tấn công khó nhận thấy khi quá trình xác thực quá dễ dãi, có trạng thái hoặc không nhất quán với các quy tắc mô phỏng của bundler.

## 1) Bypass bằng cách gọi trực tiếp các hàm đặc quyền
Bất kỳ hàm `execute` (hoặc hàm chuyển tiền) nào có thể được gọi từ bên ngoài mà không bị giới hạn chỉ cho `EntryPoint` (hoặc một executor module đã được kiểm tra) đều có thể bị gọi trực tiếp để rút hết tiền trong tài khoản.<sup>[[2]](#references)</sup>

```solidity
function execute(address target, uint256 value, bytes calldata data) external {
    (bool ok,) = target.call{value: value}(data);
    require(ok, "exec failed");
}
```

Mẫu an toàn: giới hạn quyền truy cập cho `EntryPoint`, và dùng `msg.sender == address(this)` cho các luồng quản trị/tự quản lý (cài đặt module, thay đổi validator, nâng cấp).<sup>[[2]](#references)[[5]](#references)</sup>

```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
    require(msg.sender == entryPoint, "not entryPoint");
    (bool ok,) = target.call{value: value}(data);
    require(ok, "exec failed");
}
```

## 2) Trường gas không được ký hoặc kiểm tra -> thất thoát phí
Nếu quá trình xác thực chữ ký chỉ bao gồm ý định (`callData`) mà không bao gồm các trường liên quan đến gas, bundler hoặc frontrunner có thể tăng phí và rút cạn ETH. Payload được ký phải ràng buộc ít nhất các trường sau:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Biện pháp phòng vệ: sử dụng `userOpHash` do `EntryPoint` cung cấp (bao gồm các trường gas) và/hoặc giới hạn nghiêm ngặt từng trường.<sup>[[2]](#references)[[5]](#references)</sup>

```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
    external
    returns (uint256)
{
    require(_isApprovedCall(userOpHash, op.signature), "bad sig");
    return 0;
}
```

## 3) Ghi đè trạng thái validation (ngữ nghĩa bundle)
Vì tất cả các bước validation chạy trước khi thực thi, việc lưu kết quả validation vào state của contract là không an toàn. Một op khác trong cùng bundle có thể ghi đè kết quả đó, khiến quá trình thực thi của bạn sử dụng state chịu ảnh hưởng của attacker.<sup>[[2]](#references)</sup>

Tránh ghi vào storage trong `validateUserOp`. Nếu không thể tránh, hãy khóa dữ liệu tạm thời theo `userOpHash` và xóa dữ liệu một cách xác định sau khi sử dụng (ưu tiên validation stateless).<sup>[[2]](#references)</sup>

## 4) Replay ERC-1271 giữa các account/chain (thiếu domain separation)
`isValidSignature(bytes32 hash, bytes sig)` phải ràng buộc chữ ký với **contract này** và **chain này**. Khôi phục chữ ký từ một hash thô cho phép replay giữa các account hoặc chain.<sup>[[1]](#references)[[4]](#references)</sup>

Dùng typed data EIP-712 (domain bao gồm `verifyingContract` và `chainId`) và trả về chính xác magic value ERC-1271 `0x1626ba7e` khi thành công.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Revert không hoàn phí sau validation
Khi `validateUserOp` thành công, phí đã được cam kết ngay cả khi quá trình thực thi sau đó revert. Attacker có thể liên tục gửi các op sẽ thất bại mà vẫn thu phí từ account.<sup>[[2]](#references)</sup>

Đối với paymaster, việc thanh toán từ một pool dùng chung trong `validateUserOp` rồi tính phí người dùng trong `postOp` rất mong manh vì `postOp` có thể revert mà không hoàn tác khoản thanh toán. Hãy bảo đảm nguồn tiền trong quá trình validation (escrow/deposit riêng cho từng người dùng), giữ `postOp` tối giản và không revert, đồng thời dự trù `paymasterPostOpGasLimit` cho trường hợp hoàn trả tốn gas nhất.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Giả định về triển khai counterfactual / factory
`UserOperation` đầu tiên thường chứa `initCode`, khiến account được triển khai thông qua một **factory** trong quá trình validation. Đường đi này dễ bị kiểm tra thiếu vì chỉ chạy trong lần sử dụng đầu tiên.<sup>[[5]](#references)</sup>

Các lỗi thường gặp bao gồm:<sup>[[5]](#references)</sup>

- Factory/initializer tin rằng `msg.sender == entryPoint`, nhưng đường triển khai ERC-4337 **không** gọi trực tiếp `initCode` từ `EntryPoint`.
- Salt, owner, validator hoặc cấu hình module không được ràng buộc đầy đủ với ý định đã ký, nên một frontrunner có thể chạy đua để triển khai lần đầu và chiếm địa chỉ counterfactual bằng các thiết lập do attacker kiểm soát.
- Factory không idempotent, khiến luồng sử dụng lần đầu lặp lại làm hỏng wallet thay vì trả về địa chỉ đã được tạo.

Mẫu an toàn: tính lại sender dự kiến từ các tham số triển khai đã ký, triển khai theo cách xác định (thường dùng `CREATE2`) và chỉ cho phép khởi tạo một lần.<sup>[[5]](#references)</sup>

```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```

## 7) Logic xác thực mà bundler từ chối
Mã xác thực có thể đúng trong các bài kiểm thử cục bộ nhưng vẫn không dùng được với bundler thực tế. Bundler chạy xác thực nhiều lần và nên thực hiện xác thực toàn bundle có trace trước khi gửi.<sup>[[6]](#references)</sup>

Theo các quy tắc về phạm vi xác thực này, những mẫu sau rất nguy hiểm:<sup>[[6]](#references)</sup>

- Các opcode phụ thuộc vào block như `TIMESTAMP`, `NUMBER` hoặc `BLOCKHASH`
- Truy cập storage nằm ngoài phạm vi account/entity được phép, hoặc lặp qua storage không giới hạn
- Các lệnh gọi bên ngoài hoặc truy vấn oracle phụ thuộc vào trạng thái có thể thay đổi bên ngoài phạm vi xác thực được phép

Ví dụ không an toàn:

```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
    external
    returns (uint256)
{
    require(block.timestamp < expiry, "expired");
    seen[userOpHash] = true; // stateful validation can be clobbered by another op
    require(oracle.isAllowed(op.sender), "oracle changed");
    return 0;
}
```

Xem validation là một hàm kiểm tra trước xác định và có giới hạn. Nếu cần trạng thái dùng chung hoặc tra cứu bên ngoài, hãy tuân thủ các quy tắc về staked-entity và kiểm thử cùng đường mô phỏng bundler nhiều lượt, không chỉ chạy unit test.<sup>[[6]](#references)</sup>

## 8) Front-run khởi tạo ERC-7702
ERC-7702 cấp cho EOA một ủy quyền lâu dài đến mã smart-account; việc ủy quyền không chạy quá trình khởi tạo một cách nguyên tử. Nếu có thể gọi hàm khởi tạo từ bên ngoài, một người quan sát có thể front-run hàm này và đặt chính họ làm owner.<sup>[[7]](#references)</sup>

Biện pháp giảm thiểu: yêu cầu calldata khởi tạo được EOA cho phép và chỉ cho phép khởi tạo một lần. Trong luồng ERC-4337 EIP-7702, đồng thời giới hạn caller là `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>

```solidity
function initialize(address newOwner, bytes calldata initSig) external {
    require(owner == address(0), "already inited");
    // Verify the EOA's signature over the complete initialization calldata.
    require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
    owner = newOwner;
}
```

## Kiểm tra nhanh trước khi merge
- Xác thực chữ ký bằng `userOpHash` của `EntryPoint` (ràng buộc các trường gas).
- Giới hạn các hàm đặc quyền chỉ cho `EntryPoint` và/hoặc `address(this)` khi phù hợp.
- Giữ `validateUserOp` không trạng thái, xác định và tương thích với các quy tắc mô phỏng của bundler.
- Thực thi phân tách domain EIP-712 cho ERC-1271 và trả về `0x1626ba7e` khi thành công.
- Giữ `postOp` tối giản, có giới hạn và không revert; bảo đảm an toàn cho phí trong quá trình validation.
- Kiểm thử riêng đường dẫn `initCode` đầu tiên: triển khai xác định, factory có hành vi idempotent và khởi tạo một lần duy nhất.
- Chạy validation nhiều lượt của bundler và kiểm tra toàn bộ bundle có trace trước khi phát hành.
- Với ERC-7702, ràng buộc init với ủy quyền của EOA và chỉ cho phép thực hiện một lần; trong các luồng ERC-4337, giới hạn caller là `EntryPoint.senderCreator()`.

## References

- [1] [Replay ERC1271 - Ảnh hưởng đến hơn 15 đội ngũ (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Sáu sai lầm trong smart account ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Phương thức xác thực chữ ký tiêu chuẩn cho contract](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Băm và ký dữ liệu có cấu trúc theo kiểu](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Trừu tượng hóa tài khoản bằng Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Quy tắc phạm vi validation cho trừu tượng hóa tài khoản](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Thiết lập code cho EOA](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
