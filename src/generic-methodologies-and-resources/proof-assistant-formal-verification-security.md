# Bảo mật Proof Assistant và xác minh hình thức

{{#include ../banners/hacktricks-training.md}}

Proof assistant có thể thực thi cùng một term qua nhiều đường: kernel reduction, interpreter, code được tạo, runtime primitive hoặc checker bên ngoài. Proof chỉ mạnh ngang với mọi thành phần được phép đóng góp kết quả đáng tin cậy. Trong Lean, các native decision procedure đánh đổi tốc độ đánh giá để lấy trusted computing base (TCB) lớn hơn: compiler và các định nghĩa có native implementation trở nên quan trọng đối với tính toàn vẹn của proof.<sup>[[3]](#references)</sup>

## Đánh giá vi sai giữa logic và native

Ưu tiên các primitive có implementation thực thi khác với mô hình logic của chúng (ví dụ compiler intrinsic, foreign-function interface, runtime override và các định nghĩa được đánh dấu bằng `@[implemented_by]`). Đánh giá vi sai **cùng một term đóng** qua đường logic và đường biên dịch, đồng thời xem mọi khác biệt về giá trị, exception hoặc việc kết thúc là một phát hiện bảo mật.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Các nhóm giá trị biên hữu ích gồm:<sup>[[1]](#references)[[4]](#references)</sup>

- index quanh `0`, độ dài đầu vào, giới hạn machine-word và các giá trị như `2^63` trở lên;
- các range có độ dài 0/1 byte, `start = end`, `start > end` và vị trí nằm xa ngoài object;
- đầu vào rỗng và không rỗng, chuỗi nhiều byte, ranh giới không hợp lệ và phép toán số học có thể bị cắt cụt khi biên dịch;
- giá trị được cấp phát trên heap khi native primitive có hành vi ownership hoặc borrowing không có trong mô hình logic.

Mẫu Lean rút gọn sau minh họa vấn đề được phát hiện trong `String.Pos.Raw.extract`: native code dễ bị lỗi trả về chuỗi gốc cho một range một byte cực lớn, trong khi definitional reduction trả về chuỗi rỗng. Sai khác ngữ nghĩa này được sửa riêng với lỗi an toàn bộ nhớ liên quan.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

```lean
def value : String := "non-empty"
def startPos : String.Pos.Raw := ⟨2^63⟩
def endPos : String.Pos.Raw := ⟨2^63 + 1⟩

example : False := by
  have logical : String.Pos.Raw.extract value startPos endPos = "" := rfl
  have native : String.Pos.Raw.extract value startPos endPos = value := by
    native_decide
  exact (by decide) (logical.symm.trans native)
```

Mẫu này tổng quát hóa vượt ra ngoài chuỗi: nếu đánh giá logic chứng minh `E = A` và đánh giá native đáng tin cậy chứng minh `E = B`, thì tính bắc cầu cho ra `A = B`. Khi `A` và `B` khác biệt có thể quan sát được, điều này dẫn đến `False`; sau đó, `False.elim` (nguyên lý bùng nổ) có thể chứng minh bất kỳ mệnh đề đích nào. Kernel không cần có quy tắc rút gọn sai—lỗi toàn vẹn xảy ra vì một kết quả dựa trên compiler đã đi vào logic thông qua một tiên đề.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Kiểm tra TCB mở rộng trong Lean

Không dùng dấu kiểm trong editor hoặc một lần build thành công làm cách xác thực duy nhất cho một proof không đáng tin cậy. Kiểm tra toàn bộ closure phụ thuộc của từng định lý quan trọng về bảo mật bằng `#print axioms`; hướng dẫn xác thực của Lean xác định các tên `_native` là phụ thuộc vào đánh giá native, `sorryAx` là proof chưa hoàn chỉnh, và các tên không chuẩn khác là custom axioms.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

Ví dụ, một phụ thuộc được tạo ra giống như sau có nghĩa là quá trình thực thi đã biên dịch đóng góp một kết quả được giả định, thay vì một chứng minh chỉ được suy ra bằng phép rút gọn của kernel:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Trong quá trình rà soát mã nguồn, hãy tìm các thủ tục quyết định gốc và các cơ chế thoát tường minh, nhưng xác nhận kết quả bằng `#print axioms` vì các phụ thuộc có thể gián tiếp hoặc được tạo tự động:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Phân biệt các lớp khi phân loại một phát hiện:<sup>[[3]](#references)</sup>

1. **Tính toàn vẹn của mệnh đề:** xác minh ký hiệu, các instance của type class, imports và định nghĩa thể hiện đúng mệnh đề dự định.
2. **Các phụ thuộc của chứng minh:** từ chối hoặc xem xét rõ ràng các tiên đề bất ngờ, đặc biệt là các tiên đề native-evaluation được tạo tự động.
3. **Phát lại bằng kernel:** sau `lake build`, chạy `lean4checker --fresh <Module>` để phát lại các khai báo từ tệp `.olean`.
4. **Xác thực chứng minh độc hại:** build mã không đáng tin cậy trong sandbox và dùng `lake comparator` cùng các checker bên ngoài để kiểm tra một mệnh đề thử thách đáng tin cậy.

`lean4checker` cung cấp thêm một lớp phòng vệ hữu ích, nhưng tin cậy vào tính đúng đắn về cấu trúc của các tệp `.olean`; việc chạy meta-code Lean không đáng tin cậy cũng có thể tự làm tổn hại môi trường kiểm tra. Với các chứng minh có rủi ro cao, comparator xuất chứng minh ra ngoài sandbox, đối chiếu mệnh đề với thử thách đáng tin cậy và có thể phát lại chứng minh qua các checker được triển khai độc lập; sự đa dạng trong triển khai làm giảm khả năng một lỗi của compiler, runtime hoặc kernel khiến cùng một kết quả sai được xác thực ở mọi nơi.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract` sai khác giữa mô hình/runtime và use-after-free - Lean issue #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [Sửa lỗi sai khác giữa mô hình/runtime của `String.Pos.Raw.extract` - Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Tài liệu tham khảo ngôn ngữ Lean: Xác thực một chứng minh Lean](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [Một “chứng minh” Định lý cuối cùng của Fermat vừa khít lề trang](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
