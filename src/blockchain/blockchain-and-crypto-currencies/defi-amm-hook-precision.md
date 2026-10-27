# Khai thác DeFi/AMM: Lạm dụng độ chính xác/làm tròn của Hook Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Trang này ghi lại một nhóm kỹ thuật khai thác DeFi/AMM nhằm vào các DEX kiểu Uniswap v4, mở rộng phép toán cốt lõi bằng các hook tùy chỉnh. Sự cố Bunni V2 minh họa một lỗi tương tự: lỗi hướng làm tròn trong cách tính toán rút tiền đã tính thấp hơn thanh khoản đang hoạt động; sau đó, một swap làm lộ phần tính thiếu này trong một sandwich có lợi.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ý tưởng chính: nếu một hook thực hiện kế toán bổ sung dựa trên phép toán fixed-point, làm tròn tick và logic ngưỡng, kẻ tấn công có thể tạo các swap exact-input vượt qua những ngưỡng cụ thể, khiến sai lệch làm tròn tích lũy theo hướng có lợi cho họ. Lặp lại mẫu này rồi rút số dư đã bị thổi phồng sẽ hiện thực hóa lợi nhuận, thường được tài trợ bằng flash loan.

## Bối cảnh: hook Uniswap v4 và luồng swap

- Hook là các contract mà PoolManager gọi tại những điểm cụ thể trong vòng đời (ví dụ: beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pool được khởi tạo với một PoolKey bao gồm contract hook. Địa chỉ hook khác 0 sẽ kích hoạt các callback được chọn cho pool đó.<sup>[[4]](#references)[[14]](#references)</sup>
- Hook có thể trả về **custom delta** để sửa đổi các thay đổi số dư cuối cùng của một swap hoặc hành động thanh khoản (custom accounting). Các delta này được thanh toán dưới dạng số dư ròng khi kết thúc lời gọi, nên mọi lỗi làm tròn trong phép toán của hook sẽ tích lũy trước khi thanh toán.<sup>[[4]](#references)</sup>
- Phép toán cốt lõi sử dụng các định dạng fixed-point như Q64.96 cho sqrtPriceX96 và phép tính tick với 1.0001^tick. Mọi phép toán tùy chỉnh được xây dựng trên đó phải khớp chính xác quy tắc làm tròn để tránh làm sai lệch bất biến.<sup>[[12]](#references)[[13]](#references)</sup>
- Swap có thể là exactInput hoặc exactOutput. Trong v3/v4, giá di chuyển theo các tick; vượt qua ranh giới tick có thể kích hoạt/vô hiệu hóa thanh khoản trong range. Hook có thể triển khai logic bổ sung khi vượt ngưỡng/tick.<sup>[[9]](#references)[[11]](#references)</sup>

## Dạng lỗ hổng: sai lệch độ chính xác/làm tròn khi vượt ngưỡng

Một mẫu dễ bị tấn công thường gặp trong hook tùy chỉnh:

1. Hook tính các delta thanh khoản hoặc số dư cho mỗi swap bằng phép chia số nguyên, mulDiv hoặc chuyển đổi fixed-point (ví dụ: chuyển token ↔ thanh khoản bằng sqrtPrice và các khoảng tick).
2. Logic ngưỡng (ví dụ: cân bằng lại, phân phối lại theo bước hoặc kích hoạt theo từng range) được kích hoạt khi quy mô swap hoặc biến động giá vượt qua một ranh giới nội bộ.
3. Làm tròn được áp dụng không nhất quán (ví dụ: cắt về 0, floor so với ceil) giữa phép tính xuôi và luồng thanh toán. Sai lệch nhỏ không triệt tiêu nhau mà thay vào đó ghi có cho người gọi.
4. Các swap exact-input được định cỡ chính xác để vượt qua những ranh giới đó liên tục thu về phần dư làm tròn dương. Sau đó, kẻ tấn công rút khoản ghi có tích lũy.

Điều kiện tiên quyết của cuộc tấn công
- Pool sử dụng hook v4 tùy chỉnh thực hiện phép toán bổ sung cho mỗi swap (ví dụ: LDF/rebalancer).
- Có ít nhất một luồng thực thi mà việc làm tròn có lợi cho bên khởi tạo swap khi vượt qua các ngưỡng.
- Có thể lặp lại nhiều swap một cách nguyên tử (flash loan là lựa chọn lý tưởng để cung cấp vốn tạm thời và phân bổ chi phí gas). 

## Phương pháp tấn công thực tế

1) Xác định các pool tiềm năng có hook
- Liệt kê các pool v4 và kiểm tra PoolKey.hooks != address(0).
- Kiểm tra bytecode/ABI của hook để tìm callback: beforeSwap/afterSwap và các phương thức cân bằng lại tùy chỉnh.
- Tìm các phép toán có đặc điểm: chia cho thanh khoản, chuyển đổi giữa lượng token và thanh khoản, hoặc tổng hợp BalanceDelta có làm tròn.

2) Mô hình hóa phép toán và ngưỡng của hook
- Tái tạo công thức thanh khoản/phân phối lại của hook: đầu vào thường bao gồm sqrtPriceX96, tickLower/Upper, currentTick, fee tier và thanh khoản ròng.
- Xác định các hàm ngưỡng/bước: tick, ranh giới bucket hoặc điểm gãy LDF. Xác định delta được làm tròn theo hướng nào ở mỗi phía của ranh giới.
- Xác định nơi chuyển đổi kiểu giữa uint256/int256, sử dụng SafeCast hoặc dựa vào mulDiv với phép làm tròn floor ngầm định.

3) Hiệu chỉnh swap exact-input để vượt qua ranh giới
- Dùng mô phỏng Foundry/Hardhat để tính Δin tối thiểu cần thiết nhằm đẩy giá vừa vượt qua một ranh giới và kích hoạt nhánh của hook.
- Xác minh rằng sauSwap, quá trình thanh toán ghi có cho người gọi nhiều hơn chi phí, để lại BalanceDelta dương hoặc khoản ghi có trong phần kế toán của hook.
- Lặp lại các swap để tích lũy khoản ghi có; sau đó gọi luồng rút tiền/thanh toán của hook.

Trong v4, vòng lặp swap phải chạy từ callback mở khóa của PoolManager; `amountSpecified` âm biểu thị exact input, và `sqrtPriceLimitX96` phải nằm строго bên trong phạm vi hợp lệ. Giới hạn giá bằng 0 sẽ revert, vì vậy pseudocode bên dưới dùng cận dưới cho swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Ví dụ harness kiểm thử kiểu Foundry (pseudocode)
```solidity
function test_precision_rounding_abuse() public {
    // 1) Arrange: set up pool with hook
    PoolKey memory key = PoolKey({
        currency0: USDC,
        currency1: USDT,
        fee: 500, // 0.05%
        tickSpacing: 10,
        hooks: IHooks(address(bunniHook))
    });
    pm.initialize(key, initialSqrtPriceX96);

    // 2) Determine a boundary‑crossing exactInput
    uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

    // 3) Loop swaps to accrue rounding credit
    // This loop runs inside the PoolManager unlockCallback.
    for (uint i; i < N; ++i) {
        pm.swap(
            key,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -int256(exactIn), // exactInput
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1 // allow movement to the lower bound
            }),
            ""
        );
    }

    // 4) Realize inflated credit via hook‑exposed withdrawal
    bunniHook.withdrawCredits(msg.sender);
}
```

Hiệu chỉnh exactInput
- Tính mục tiêu bằng TickMath lõi: sqrtP_next = sqrtP_current × 1.0001^(Δtick) theo giá trị thực; kết quả Q64.96 được TickMath làm tròn.<sup>[[13]](#references)</sup>
- Ước tính lượng đầu vào token0 (zero-for-one) bằng công thức có xét Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Khớp với cách làm tròn theo hướng của routine lõi.<sup>[[12]](#references)</sup>
- Điều chỉnh Δin ±1 wei quanh ngưỡng để tìm nhánh mà hook làm tròn theo hướng có lợi cho bạn.

4) Khuếch đại bằng flash loan
- Vay một khoản danh nghĩa lớn (ví dụ: 3M USDT hoặc 2000 WETH) để thực hiện nhiều vòng lặp trong cùng một giao dịch nguyên tử.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Thực hiện vòng lặp swap đã hiệu chỉnh, sau đó rút và hoàn trả trong callback của flash loan.

Khung flash loan Aave V3
```solidity
function executeOperation(
    address[] calldata assets,
    uint256[] calldata amounts,
    uint256[] calldata premiums,
    address initiator,
    bytes calldata params
) external returns (bool) {
    // run threshold‑crossing swap loop here
    for (uint i; i < N; ++i) {
        _exactInBoundaryCrossingSwap();
    }
    // realize credits / withdraw inflated balances
    bunniHook.withdrawCredits(address(this));
    // repay
    for (uint j; j < assets.length; ++j) {
        IERC20(assets[j]).approve(address(POOL), amounts[j] + premiums[j]);
    }
    return true;
}
```

5) Thoát và tái hiện xuyên chuỗi
- Nếu hook được triển khai trên nhiều chain, hãy lặp lại quy trình hiệu chỉnh tương tự cho từng chain.
- Trong sự cố Bunni, thanh khoản flash-loan và các tuyến bridge khác nhau tùy chain, vì vậy hãy tính đến các ràng buộc riêng của từng chain khi tái hiện phân tích.<sup>[[1]](#references)[[2]](#references)</sup>

## Các nguyên nhân gốc phổ biến trong phép tính của hook

- Ngữ nghĩa làm tròn không nhất quán: mulDiv làm tròn xuống, trong khi các nhánh xử lý sau đó thực tế làm tròn lên; hoặc các phép chuyển đổi giữa token/thanh khoản áp dụng cách làm tròn khác nhau.
- Lỗi căn chỉnh tick: dùng tick chưa làm tròn ở một nhánh và làm tròn theo khoảng tick ở nhánh khác.
- Lỗi dấu/tràn BalanceDelta khi chuyển đổi giữa int256 và uint256 trong quá trình thanh toán.
- Mất độ chính xác khi chuyển đổi Q64.96 (sqrtPriceX96), nhưng không được phản ánh tương ứng trong ánh xạ ngược.
- Các luồng tích lũy: phần dư theo từng giao dịch swap được ghi nhận thành khoản tín dụng mà caller có thể rút, thay vì bị đốt hoặc được cân bằng tổng bằng 0.

## Kế toán tùy chỉnh & khuếch đại delta

- Cơ chế kế toán tùy chỉnh của Uniswap v4 cho phép hook trả về các delta trực tiếp điều chỉnh khoản caller phải trả/nhận. Nếu hook theo dõi các khoản tín dụng nội bộ, phần dư do làm tròn có thể tích lũy qua nhiều thao tác nhỏ **trước khi** quyết toán cuối cùng diễn ra.<sup>[[4]](#references)</sup>
- Nếu hook cung cấp một đường rút tương thích, kẻ tấn công có thể luân phiên `swap → withdraw → swap` trong cùng callback unlock của PoolManager, buộc hook tính toán lại delta trên trạng thái hơi khác trong khi số dư vẫn đang chờ cho đến khi unlock được quyết toán.<sup>[[4]](#references)[[10]](#references)</sup>
- Khi kiểm tra hook, hãy luôn lần theo cách BalanceDelta/HookDelta được tạo ra và quyết toán. Chỉ một phép làm tròn thiên lệch trong một nhánh cũng có thể trở thành khoản tín dụng cộng dồn khi delta liên tục được tính toán lại.

## Hướng dẫn phòng thủ

- Kiểm thử vi sai: đối chiếu phép tính của hook với một triển khai tham chiếu dùng số học phân số độ chính xác cao, đồng thời xác nhận kết quả bằng nhau hoặc sai số có giới hạn và luôn bất lợi cho caller.
- Kiểm thử bất biến/thuộc tính:
  - Tổng delta (token, thanh khoản) trên các luồng swap và các điều chỉnh của hook phải bảo toàn giá trị, ngoại trừ phí.
  - Không nhánh nào được tạo ra khoản tín dụng ròng dương cho bên khởi tạo swap qua nhiều lần lặp exactInput.
  - Kiểm thử ngưỡng/ranh giới tick với đầu vào ±1 wei cho cả exactInput/exactOutput.
- Chính sách làm tròn: tập trung các hàm hỗ trợ làm tròn để luôn làm tròn theo hướng bất lợi cho người dùng; loại bỏ các phép ép kiểu không nhất quán và phép làm tròn xuống ngầm định.
- Nơi tiếp nhận khoản dư khi quyết toán: chuyển phần dư do làm tròn không thể tránh khỏi vào kho bạc giao thức hoặc đốt; không bao giờ ghi nhận khoản đó cho msg.sender.
- Giới hạn tốc độ/biện pháp bảo vệ: đặt kích thước swap tối thiểu cho các trigger tái cân bằng; tắt tái cân bằng nếu delta nhỏ hơn một wei; kiểm tra tính hợp lý của delta so với phạm vi dự kiến.
- Rà soát toàn diện các callback của hook: beforeSwap/afterSwap và các callback trước/sau khi thay đổi thanh khoản phải thống nhất về căn chỉnh tick và cách làm tròn delta.

## Nghiên cứu tình huống: Bunni V2 (2025‑09‑02)

- Giao thức: Bunni V2, một hook của Uniswap v4 sử dụng Liquidity Density Function (LDF) để tính mật độ token và ước tính tổng thanh khoản.<sup>[[1]](#references)[[2]](#references)</sup>
- Các pool bị ảnh hưởng: USDC/USDT trên Ethereum và weETH/ETH trên Unichain, tổng cộng khoảng $8.4M.<sup>[[1]](#references)</sup>
- Bước 1 (đẩy giá): kẻ tấn công flash-borrow ~3M USDT rồi swap để đẩy tick lên ~5000, làm số dư USDC **active** giảm xuống còn ~28 wei.<sup>[[1]](#references)</sup>
- Bước 2 (rút cạn do làm tròn): 44 lần rút nhỏ khai thác phép làm tròn xuống trong `BunniHubLogic::withdraw()` để giảm số dư USDC active từ 28 wei xuống 4 wei (-85.7%), trong khi chỉ một phần rất nhỏ cổ phần LP bị đốt. Tổng thanh khoản giảm ~84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Bước 3 (sandwich khi thanh khoản phục hồi): một giao dịch swap lớn đẩy tick lên ~839,189 (1 USDC ≈ 2.77e36 USDT). Các ước tính thanh khoản đảo chiều và tăng ~16.8%, tạo điều kiện cho một cuộc tấn công sandwich, trong đó kẻ tấn công swap ngược lại ở mức giá bị thổi phồng rồi thoát ra với lợi nhuận.<sup>[[1]](#references)</sup>
- Bản sửa được xác định trong báo cáo hậu kiểm: thay đổi cập nhật số dư nhàn rỗi để làm tròn **lên**, nhờ đó các lần rút siêu nhỏ lặp lại không còn liên tục kéo giảm số dư active của pool.<sup>[[1]](#references)</sup>

Dòng mã dễ bị tổn thương đã được đơn giản hóa (và bản sửa trong báo cáo hậu kiểm).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Checklist săn tìm

- Pool có sử dụng địa chỉ hooks khác 0 không? Những callback nào được bật?
- Có phân phối lại/tái cân bằng theo từng swap bằng phép tính tùy chỉnh không? Có logic tick/ngưỡng nào không?
- Các phép chia/mulDiv, chuyển đổi Q64.96 hoặc SafeCast được dùng ở đâu? Quy tắc làm tròn có nhất quán trên toàn hệ thống không?
- Bạn có thể tạo Δin vừa đủ vượt qua một ranh giới để nhận được nhánh làm tròn có lợi không? Hãy kiểm tra cả hai chiều và cả exactInput lẫn exactOutput.
- Hook có theo dõi khoản tín dụng hoặc delta riêng cho từng caller để có thể rút sau này không? Đảm bảo phần dư được triệt tiêu.

## References

- [1] [Báo cáo hậu kiểm về vụ khai thác Bunni (tháng 9 năm 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Vụ khai thác Bunni V2: Phân tích đầy đủ vụ hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Vụ khai thác Bunni V2: Rút cạn 8,3 triệu USD qua lỗi thanh khoản (tóm tắt)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Sách trắng Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Thông tin nền về Uniswap v4 (nghiên cứu của QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Cơ chế thanh khoản trong Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Cơ chế swap trong Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks của Uniswap v4 và các cân nhắc về bảo mật](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol của Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol của Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams của Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol của Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol của Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey của Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
