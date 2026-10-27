# Kiểm thử mutation cho Smart Contract (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Kiểm thử mutation “kiểm thử các bài kiểm thử của bạn” bằng cách lần lượt đưa những thay đổi nhỏ (mutant) vào mã contract rồi chạy lại bộ kiểm thử. Nếu một bài kiểm thử thất bại, mutant bị tiêu diệt. Nếu các bài kiểm thử vẫn vượt qua, mutant tồn tại, cho thấy điểm mù mà độ bao phủ dòng/nhánh không thể phát hiện.

Ý tưởng chính: Độ bao phủ cho biết mã đã được thực thi; kiểm thử mutation cho biết hành vi có thực sự được kiểm tra hay không.<sup>[[2]](#references)</sup>

## Vì sao độ bao phủ có thể đánh lừa

Hãy xem xét phép kiểm tra ngưỡng đơn giản sau:

```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
    if (deposit >= 1 ether) {
        return true;
    } else {
        return false;
    }
}
```

Các unit test chỉ kiểm tra một giá trị thấp hơn và một giá trị cao hơn ngưỡng có thể đạt 100% độ bao phủ dòng/nhánh nhưng không xác nhận ranh giới bằng nhau (`==`). Nếu refactor thành `deposit >= 2 ether`, các test như vậy vẫn vượt qua, âm thầm làm sai logic của giao thức.<sup>[[2]](#references)</sup>

Mutation testing phát hiện lỗ hổng này bằng cách thay đổi điều kiện rồi xác minh rằng các test thất bại.

Với smart contract, các mutant còn tồn tại thường chỉ ra những kiểm tra còn thiếu liên quan đến:
- Quyền hạn và ranh giới vai trò
- Các bất biến về kế toán/chuyển giá trị
- Điều kiện revert và các nhánh lỗi
- Điều kiện biên (`==`, giá trị 0, mảng rỗng, giá trị tối đa/tối thiểu)

## Các toán tử mutation có tín hiệu bảo mật cao nhất

Các lớp mutation hữu ích khi audit contract:<sup>[[1]](#references)[[2]](#references)</sup>
- **Mức độ nghiêm trọng cao**: thay các câu lệnh bằng `revert()` để phát hiện những nhánh chưa được thực thi
- **Mức độ nghiêm trọng trung bình**: chú thích các dòng / xóa logic để phát hiện các tác động phụ chưa được xác minh
- **Mức độ nghiêm trọng thấp**: thay đổi toán tử hoặc hằng số một cách tinh vi, chẳng hạn `>=` -> `>` hoặc `+` -> `-`
- Các chỉnh sửa phổ biến khác: thay phép gán, đảo giá trị boolean, phủ định điều kiện và thay đổi kiểu dữ liệu

Mục tiêu thực tế: loại bỏ tất cả mutant có ý nghĩa và giải thích rõ những mutant còn tồn tại nhưng không liên quan hoặc tương đương về mặt ngữ nghĩa.

## Vì sao mutation nhận biết cú pháp tốt hơn regex

Các công cụ mutation đời cũ dựa vào regex hoặc cách viết lại theo từng dòng. Cách này có hiệu quả nhưng có những hạn chế đáng kể:<sup>[[1]](#references)</sup>
- Khó mutation các câu lệnh nhiều dòng một cách an toàn
- Không hiểu cấu trúc ngôn ngữ, nên có thể nhắm sai vào comment/token
- Việc tạo mọi biến thể có thể có trên một dòng yếu kém sẽ lãng phí rất nhiều thời gian chạy

Các công cụ dựa trên AST hoặc Tree-sitter cải thiện việc này bằng cách nhắm đến các node có cấu trúc thay vì các dòng thô:<sup>[[1]](#references)</sup>
- **slither-mutate** sử dụng AST Solidity của Slither.<sup>[[4]](#references)</sup>
- **mewt** sử dụng Tree-sitter làm lõi độc lập với ngôn ngữ.<sup>[[6]](#references)</sup>
- **MuTON** được xây dựng dựa trên `mewt` và bổ sung hỗ trợ trực tiếp cho các ngôn ngữ TON như FunC, Tolk và Tact.<sup>[[7]](#references)</sup>

Nhờ vậy, các cấu trúc nhiều dòng và mutation ở cấp biểu thức đáng tin cậy hơn nhiều so với các phương pháp chỉ dùng regex.

## Chạy mutation testing với slither-mutate

Yêu cầu: Slither v0.10.2+.

- Liệt kê tùy chọn và mutator:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Ví dụ Foundry (ghi lại kết quả và lưu nhật ký đầy đủ):<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- Nếu không dùng Foundry, hãy thay `--test-cmd` bằng lệnh chạy test của bạn (ví dụ: `npx hardhat test`, `npm test`).

Theo mặc định, artifacts được lưu trong `./mutation_campaign`. Các mutant chưa bị bắt (còn tồn tại) sẽ được sao chép vào đó để kiểm tra.<sup>[[5]](#references)</sup>

### Tìm hiểu output

Các dòng báo cáo có dạng:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- Thẻ trong ngoặc là bí danh của mutator (ví dụ: `CR` = Comment Replacement).
- `UNCAUGHT` nghĩa là các bài kiểm thử đã vượt qua với hành vi đã bị mutation → thiếu assertion.

## Giảm thời gian chạy: ưu tiên các mutant có ảnh hưởng lớn

Các chiến dịch mutation testing có thể kéo dài hàng giờ hoặc hàng ngày. Mẹo để giảm chi phí:<sup>[[1]](#references)[[2]](#references)</sup>
- Phạm vi: Chỉ bắt đầu với các contract/thư mục quan trọng, sau đó mở rộng.
- Ưu tiên mutator: Nếu một mutant ưu tiên cao trên một dòng vẫn còn tồn tại (ví dụ `revert()` hoặc comment-out), hãy bỏ qua các biến thể ưu tiên thấp hơn trên dòng đó.
- Dùng chiến dịch hai giai đoạn: Trước tiên chạy các bài kiểm thử tập trung/nhanh, sau đó chỉ kiểm thử lại các mutant chưa bị phát hiện bằng toàn bộ bộ kiểm thử.
- Khi có thể, ánh xạ các mục tiêu mutation vào lệnh kiểm thử cụ thể (ví dụ: mã auth -> các bài kiểm thử auth).
- Khi không có nhiều thời gian, giới hạn chiến dịch ở các mutant có mức độ nghiêm trọng cao/trung bình.
- Chạy các bài kiểm thử song song nếu runner hỗ trợ; lưu cache dependency/build.
- Fail-fast: dừng sớm khi một thay đổi cho thấy rõ có lỗ hổng trong assertion.

Tính toán thời gian chạy rất khắc nghiệt: `1000 mutants x 5-minute tests ~= 83 hours`, vì vậy thiết kế chiến dịch cũng quan trọng như chính mutator.<sup>[[1]](#references)</sup>

## Chiến dịch bền vững và phân loại kết quả ở quy mô lớn

Một điểm yếu của các quy trình cũ là chỉ ghi kết quả ra `stdout`. Với các chiến dịch kéo dài, việc tạm dừng/tiếp tục, lọc và xem xét sẽ khó hơn.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` cải thiện điều này bằng cách lưu mutant và kết quả vào các chiến dịch dùng SQLite. Lợi ích:<sup>[[1]](#references)</sup>
- Tạm dừng và tiếp tục các lượt chạy dài mà không mất tiến độ
- Chỉ lọc các mutant chưa bị phát hiện trong một file hoặc lớp mutation cụ thể
- Xuất/chuyển đổi kết quả sang SARIF để dùng với các công cụ xem xét
- Cung cấp cho việc phân loại có AI hỗ trợ các tập kết quả nhỏ hơn, đã lọc, thay vì log thô trên terminal

Kết quả được lưu bền vững đặc biệt hữu ích khi mutation testing trở thành một phần của quy trình audit thay vì chỉ là một lần xem xét thủ công.

## Quy trình phân loại mutant còn tồn tại

1) Kiểm tra dòng đã bị mutation và hành vi của nó.
   - Tái hiện cục bộ bằng cách áp dụng dòng đã bị mutation rồi chạy một bài kiểm thử tập trung.

2) Củng cố bài kiểm thử để kiểm tra trạng thái, không chỉ giá trị trả về.
   - Thêm kiểm tra tại ranh giới bằng nhau (ví dụ: kiểm thử ngưỡng `==`).
   - Kiểm tra các điều kiện hậu: số dư, tổng nguồn cung, tác động của việc phân quyền và các event được phát ra.

3) Thay các mock quá dễ dãi bằng hành vi thực tế.
   - Đảm bảo mock kiểm tra các giao dịch chuyển, các trường hợp lỗi và việc phát event diễn ra on-chain.

4) Thêm invariant cho các bài kiểm thử fuzz.
   - Ví dụ: bảo toàn giá trị, số dư không âm, invariant về phân quyền, nguồn cung đơn điệu khi phù hợp.

5) Phân biệt true positive với semantic no-op.
   - Ví dụ: `x > 0` -> `x != 0` không có ý nghĩa khi `x` là số không dấu.

6) Chạy lại chiến dịch cho đến khi các mutant còn tồn tại bị phát hiện hoặc được giải trình rõ ràng.

## Nghiên cứu tình huống: phát hiện thiếu assertion về trạng thái (Arkis protocol)

Một chiến dịch mutation testing trong quá trình audit giao thức DeFi Arkis đã phát hiện các mutant còn tồn tại như sau:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Việc comment out phép gán không làm các bài kiểm thử thất bại, chứng tỏ thiếu các assertion về trạng thái sau. Nguyên nhân gốc: code tin cậy `_cmd.value` do người dùng kiểm soát thay vì xác thực các lần chuyển token thực tế. Kẻ tấn công có thể làm sai lệch các lần chuyển dự kiến so với thực tế để rút cạn tiền. Kết quả: rủi ro nghiêm trọng cao đối với khả năng thanh toán của protocol.<sup>[[2]](#references)[[3]](#references)</sup>

Hướng dẫn: Coi các mutant còn sống ảnh hưởng đến việc chuyển giá trị, kế toán hoặc kiểm soát truy cập là rủi ro cao cho đến khi chúng bị loại bỏ.

## Không nên tạo test một cách mù quáng để loại bỏ mọi mutant

Việc tạo test dựa trên mutation có thể phản tác dụng nếu implementation hiện tại sai. Ví dụ: thay `priority >= 2` bằng `priority > 2` làm thay đổi hành vi, nhưng cách sửa đúng không phải lúc nào cũng là “viết test cho `priority == 2`”. Chính hành vi đó có thể là lỗi.<sup>[[1]](#references)</sup>

Quy trình an toàn hơn:
- Dùng các mutant còn sống để xác định những yêu cầu còn mơ hồ
- Xác thực hành vi mong đợi dựa trên spec, tài liệu protocol hoặc ý kiến của reviewer
- Chỉ sau đó mới mã hóa hành vi thành test/invariant

Nếu không, bạn có nguy cơ biến các sự cố ngẫu nhiên trong implementation thành quy tắc cố định trong bộ test và tạo ra cảm giác an toàn giả.

## Checklist thực tế

- Chạy một chiến dịch có mục tiêu:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- Ưu tiên mutator nhận biết cú pháp (AST/Tree-sitter) thay vì chỉ dùng regex, nếu có.
- Phân loại các mutant còn sống và viết test/invariant có thể thất bại với hành vi đã bị đột biến.
- Kiểm tra số dư, nguồn cung, quyền hạn và event.
- Bổ sung test biên (`==`, tràn số/thiếu số, địa chỉ zero, số lượng zero, mảng rỗng).
- Thay thế các mock thiếu thực tế; mô phỏng các chế độ lỗi.
- Lưu kết quả nếu tooling hỗ trợ và lọc các mutant chưa được bắt trước khi phân loại.
- Dùng chiến dịch hai giai đoạn hoặc theo từng mục tiêu để kiểm soát thời gian chạy.
- Lặp lại cho đến khi mọi mutant bị loại bỏ hoặc được giải trình bằng comment và lý do.

## References

- [1] [Kiểm thử đột biến cho kỷ nguyên agentic](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Dùng kiểm thử đột biến để tìm lỗi mà test của bạn không phát hiện được (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Đánh giá bảo mật Arkis DeFi Prime Brokerage (Phụ lục C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Tài liệu Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
