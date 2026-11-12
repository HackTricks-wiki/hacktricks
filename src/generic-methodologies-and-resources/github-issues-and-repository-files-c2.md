# GitHub Issues và tệp repository làm kênh C2

{{#include ../banners/hacktricks-training.md}}

Một repository riêng tư có thể tách **trạng thái phiên** khỏi **truyền tải payload**: issues ghi lại từng host và trạng thái bắt tay, còn các tệp trong repository mang dữ liệu đã mã hóa theo cả hai chiều. Cách này không chỉ đơn giản là thăm dò nội dung issue để lấy lệnh. Triển khai được quan sát sử dụng GitHub personal access token (PAT) để truy cập cả hai API.<sup>[[1]](#references)</sup> Với fine-grained PAT, việc tạo hoặc cập nhật issues cần quyền ghi Issues, còn tải tệp lên cần quyền ghi Contents. Classic PAT cần scope `repo`. Bất kỳ ai lấy được token có đủ quyền đều có thể truy cập cùng kênh này.<sup>[[2]](#references)[[3]](#references)</sup>

## Bắt tay qua issue và tệp

Một quy trình đã được quan sát sử dụng host ID dạng hexadecimal ngắn và state machine sau. Phạm vi ID, chuỗi và tiền tố cụ thể là dấu hiệu của giao thức, không phải yêu cầu của GitHub API.<sup>[[1]](#references)</sup>

1. Khi khởi động, truy vấn các issue đang mở và đã đóng bằng `GET /repos/{owner}/{repo}/issues?state=open` (và `state=closed`) để tìm trạng thái phiên trước đó. Tạo một issue đang mở có tiêu đề `1[ID]` và nội dung `hel` bằng `POST /repos/{owner}/{repo}/issues`.
2. Đọc một tệp trong repository có tên bắt đầu bằng `2[ID]`; tệp này cung cấp public key RSA của server. Tạo session key mới dài 16 byte, mã hóa bằng RSA rồi tải kết quả lên trong một tệp có tiền tố `1[ID]`.
3. Tạo IV tiếp theo bằng cách XOR IV được nhúng với session key đó. Với mỗi tệp được trao đổi, dùng khóa ngẫu nhiên 16 byte trong tên tệp để mã hóa hoặc giải mã nội dung bằng AES. Tiền tố `2` biểu thị dữ liệu từ server đến host; tiền tố `1` biểu thị dữ liệu từ host đến server. Như vậy, tên tệp mang thông tin định tuyến và vật liệu khóa cho từng tệp, còn issue lưu trạng thái.
4. Đọc tệp tiếp theo có tiền tố `2` và yêu cầu nội dung đã giải mã phải bằng `hel`. Tải thông tin host đã mã hóa lên, sau đó đổi nội dung issue thành `hey` bằng `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. Chỉ khi đó mới bắt đầu thăm dò lệnh.

Contents API của GitHub đọc một tệp bằng `GET /repos/{owner}/{repo}/contents/{path}` và tạo hoặc thay thế tệp bằng `PUT` tại đường dẫn đó. Với tệp có kích thước tối đa 1 MB, phản hồi JSON mặc định bao gồm nội dung được mã hóa Base64; tệp có kích thước từ 1 đến 100 MB cần raw media type để lấy nội dung. Body tải lên cần có commit message và nội dung tệp được mã hóa Base64; khi thay thế một tệp hiện có, cũng cần SHA của blob hiện tại. Những chi tiết API này khác với giao thức mã hóa ở trên.<sup>[[2]](#references)[[3]](#references)</sup>

Với một repository kiểm thử được cấp phép, có thể thử nghiệm phần điều khiển issue bằng REST API (thay bằng repository kiểm thử và PAT kiểm thử). Không đưa token đang hoạt động vào URL, nội dung issue hay tệp đã commit.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

Cơ chế này **không** yêu cầu tiêu đề issue, các marker `hel`/`hey` hay các lựa chọn cipher cụ thể được trình bày ở đây; chúng chỉ xác định một cách triển khai. Ý tưởng có thể tái sử dụng là tách trạng thái host có thể thay đổi khỏi các object được mã hóa hai chiều, đồng thời liên kết cả hai với một host ID.<sup>[[1]](#references)</sup> Để xem một phương thức truyền tải khác qua GitHub issue, hãy xem [ghi chú về custom listener của AdaptixC2](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). Để xem phương án dự phòng dùng issue comment và xoay vòng thông tin xác thực của repository thay vì mang theo trạng thái phiên, hãy xem [Web services and dead-drop resolvers](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers).

## References

- [1] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – Các endpoint REST API cho issues](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – Các endpoint REST API cho nội dung repository](https://docs.github.com/en/rest/repos/contents)
