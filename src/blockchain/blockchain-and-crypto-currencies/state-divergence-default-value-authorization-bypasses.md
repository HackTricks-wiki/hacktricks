# Phân kỳ trạng thái và bypass ủy quyền bằng giá trị mặc định

{{#include ../../banners/hacktricks-training.md}}

Đôi khi việc ủy quyền phụ thuộc vào trạng thái kinh tế được suy ra thay vì một role rõ ràng—for example, "caller sở hữu toàn bộ nguồn cung." Nếu các giá trị trong điều kiện đó đến từ những nơi lưu trữ khác nhau, một bản sao cũ có thể biến lối tắt sở hữu hợp lệ thành bypass ủy quyền. Module Provenance marker đã minh họa tổ hợp nguy hiểm này: số dư hiện tại của caller được so sánh với metadata nguồn cung cục bộ của marker, vốn không được cập nhật đối với các tài sản có nguồn cung không cố định.<sup>[[1]](#references)</sup>

## Kiểm tra trạng thái trùng lặp như một ranh giới ủy quyền

Với mọi giá trị được dùng trong kiểm tra quyền, hãy liệt kê **tất cả các biểu diễn**: trạng thái module chuẩn, các trường của object, các giá trị tổng hợp được cache, index, snapshot, bản ghi bridge và bản sao ngoài chuỗi. Sau đó, lần theo mọi luồng tạo, mint, burn, transfer, reset, migration và đồng bộ hóa để xác định bản sao nào được cập nhật trong từng chế độ object. Một trường có thể là nguồn có thẩm quyền ở chế độ này nhưng chỉ mang tính thông tin ở chế độ khác.<sup>[[1]](#references)</sup>

Quy trình đánh giá thực tế:<sup>[[1]](#references)</sup>

1. Xác định các hành động được bảo vệ và rút gọn từng nhánh ủy quyền thành một điều kiện boolean.
2. Với mỗi toán hạng, ghi lại nơi lưu trữ, các luồng cập nhật, trạng thái vòng đời và nguồn dữ liệu chuẩn.
3. Tạo các chuyển đổi chỉ cập nhật một biểu diễn, rồi so sánh tất cả các bản sao.
4. Sau mỗi chuyển đổi, thử thực hiện hành động được bảo vệ từ một tài khoản mới.
5. Tiếp tục kiểm tra sau khi bypass: nếu hành động chỉnh sửa ACL, hãy tự cấp các role có hiệu lực lâu dài rồi gọi các API đặc quyền thông thường.

Các mẫu đáng ngờ gồm `cachedSupply == balance`, `metadataOwner == caller` hoặc `snapshotShares == currentShares` khi hai vế có quy tắc đồng bộ hóa khác nhau. Việc truy vấn một giá trị có thẩm quyền cho một toán hạng không khiến phép so sánh trở nên an toàn nếu toán hạng còn lại đã cũ.<sup>[[1]](#references)</sup>

## Bypass bằng so sánh với giá trị mặc định

Một điều kiện so sánh bằng cũng không an toàn khi cả hai toán hạng có thể độc lập nhận cùng một giá trị mặc định. Kiểm tra bên dưới cấp "quyền kiểm soát toàn bộ nguồn cung" cho bất kỳ tài khoản trống nào khi `supply` bằng zero, bất kể zero là do metadata cũ hay do object chưa từng được cấp vốn hợp lệ.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

Chuyển sang canonical store khắc phục tình trạng phân kỳ nhưng **không** xử lý trường hợp đối tượng rỗng. Thuộc tính bảo mật phải bao gồm một điều kiện hợp lệ độc lập; bản vá Provenance sử dụng nguồn cung thực tế của bank và từ chối nguồn cung nil hoặc bằng 0 trước khi so sánh số dư của caller.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Áp dụng cùng lập luận cho số lượng quorum, tỷ lệ sở hữu, khoản nợ, tài sản thế chấp, epoch, nonce, timestamp và bộ đếm: `callerValue == protectedValue` không được cấp quyền cho caller cho đến khi giá trị được bảo vệ được xác thực độc lập và thuộc về domain mong đợi.<sup>[[1]](#references)</sup>

## Chiếm quyền ACL để thực hiện các thao tác đặc quyền hợp lệ

Lỗ hổng bypass trong thao tác chỉnh sửa ACL là một phương thức leo thang đặc quyền lâu dài. Trong trường hợp Provenance, một tài khoản không có đặc quyền và không có token nào có thể vượt qua kiểm tra nguồn cung cũ `0 == 0`, tự cấp cho mình quyền quản trị, mint và rút tiền, rồi dùng các message handler thông thường để mint tài sản hoặc rút tiền ký quỹ. Vì vậy, sau khi thay đổi ACL, exploit không cần thêm lỗ hổng nào khác.<sup>[[1]](#references)</sup>

Trình tự khai thác tổng quát:<sup>[[1]](#references)</sup>

1. Tìm một đối tượng có trường không mang tính thẩm quyền khác với trạng thái hiện tại, hoặc có giá trị được bảo vệ là giá trị mặc định.
2. Dùng một danh tính mới/trống để giá trị cục bộ của danh tính đó khớp với giá trị cũ/mặc định.
3. Gọi endpoint quản lý vai trò, chuyển quyền sở hữu hoặc cập nhật chính sách để tự cấp các quyền lâu dài.
4. Xác nhận thay đổi vẫn tồn tại bằng cách đọc ACL từ trạng thái canonical.
5. Gọi thao tác hợp lệ có tác động lớn (mint, rút tiền, nâng cấp, chuyển quyền sở hữu hoặc thay đổi chính sách).

Khi đánh giá mức độ ảnh hưởng, hãy kiểm tra mọi quyền mà vai trò mới có thể truy cập, thay vì chỉ dừng lại ở lỗ hổng bypass xác thực. Các tài khoản dạng escrow có thể nắm giữ tài sản không liên quan đến đối tượng có metadata cũ dẫn đến việc chiếm quyền.<sup>[[1]](#references)</sup>

## Các mục tiêu bất biến và stateful-fuzzing

Đặc tả việc xác thực độc lập với phần triển khai. Với shortcut toàn bộ nguồn cung, bất biến tối thiểu là:<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

Sử dụng model/state-machine fuzzer để tạo chuỗi thao tác—không phải các lời gọi riêng lẻ—bao quát việc tạo, khởi tạo giá trị bằng không, kích hoạt/hoàn tất, mint, burn, chuyển, reset, migration, các lời gọi sync và thay đổi ACL. Sau mỗi lần chuyển trạng thái, hãy so sánh các biểu diễn trùng lặp và xác nhận rằng một tài khoản mới không thể thực hiện bất kỳ hành động nào được bảo vệ. Tạo các trường hợp cụ thể cho giá trị bằng không, một đơn vị, quyền sở hữu một phần, quyền sở hữu toàn bộ, giá trị thấp hơn thực tế và giá trị cao hơn thực tế.<sup>[[1]](#references)[[2]](#references)</sup>

Các thuộc tính hồi quy có tín hiệu cao là:<sup>[[1]](#references)[[2]](#references)</sup>

- Nguồn cung có thẩm quyền bằng không không bao giờ đồng nghĩa với quyền sở hữu hoặc quyền quản trị.
- Người nắm giữ một phần không thể trở thành quản trị viên khi nguồn cung trùng lặp bằng số dư của họ.
- Người nắm giữ toàn bộ thực sự vẫn được hưởng lối tắt dự kiến khi nguồn cung hiện tại lớn hơn không.
- Các thao tác tự cấp quyền thất bại không được làm thay đổi ACL hoặc bật các lời gọi đặc quyền ở bước sau.
- Việc thay đổi chế độ không thể âm thầm thay đổi biểu diễn mà kiểm tra phân quyền coi là có thẩm quyền.

## References

- [1] [Sai lệch trạng thái dẫn đến truy cập trái phép (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Sửa các bước kiểm tra nguồn cung cũ](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Từ chối nguồn cung bằng không trong lối tắt phân quyền theo tổng nguồn cung](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
