# Ranh giới tin cậy của tính năng tự động cập nhật Electron

{{#include ../../banners/hacktricks-training.md}}

## Bề mặt tấn công của tính năng tự động cập nhật Electron

Hãy xem updater là một ranh giới remote-code-execution: nó tải nội dung thực thi, quyết định nội dung đó có mới hơn và đáng tin cậy hay không, lưu tạm nội dung trên máy và chuyển nội dung đó cho trình cài đặt. Hãy xem xét toàn bộ đồ thị tin cậy—release index, metadata theo từng phiên bản, artifact, chữ ký detached, khóa xác minh được nhúng, bộ nhớ đệm, đường dẫn tạm và trình cài đặt—chứ không chỉ kiểm tra xem tệp `.app` cuối cùng có được ký hay không.<sup>[[1]](#references)[[2]](#references)</sup>

### Các bài kiểm tra có giá trị cao

- **Rollback/replay:** phát lại một manifest hợp lệ trước đây cùng artifact vẫn còn chữ ký hợp lệ. Chữ ký xác thực dữ liệu đầu vào nhưng không đảm bảo tính mới; client phải từ chối các phiên bản thấp hơn một ngưỡng tối thiểu tăng đơn điệu được lưu bền vững, trừ khi chính sách khôi phục đã xác thực cho phép rõ ràng việc rollback.<sup>[[2]](#references)</sup>
- **Thay thế metadata/artifact:** thay đổi riêng lẻ phiên bản, URL, hash dự kiến, artifact và chữ ký detached. Đồng thời thử ghép một cặp artifact/chữ ký hợp lệ từ một bản phát hành với metadata của bản phát hành khác. Nếu metadata bản phát hành không được ký, TLS hoặc tệp thực thi cuối cùng được ký cũng không ngăn được origin/CDN bị xâm nhập thay đổi logic lựa chọn.<sup>[[1]](#references)[[2]](#references)</sup>
- **Nhầm lẫn channel đã ký:** cung cấp bản build alpha, beta, development hoặc debug được ký hợp lệ qua feed production. Dùng lại cùng khóa và chính sách cho nhiều môi trường khiến artifact vượt qua bước kiểm tra chỉ dựa trên signer; danh tính/channel production phải nằm trong chính sách đã xác thực hoặc sử dụng trust root riêng.<sup>[[2]](#references)</sup>
- **TOCTOU với tệp tạm:** xác định xem bước xác minh có mở một pathname rồi bước cài đặt có mở lại pathname đó hay không. Nếu attacker cục bộ có thể đổi tên, thay thế hoặc chuyển hướng đối tượng đã lưu tạm giữa hai thao tác, trình cài đặt có thể tiếp nhận các byte chưa từng được xác minh. Thư mục lưu tạm ở chế độ `0700` hạn chế quyền truy cập nhưng không khiến hai thao tác trở nên nguyên tử.<sup>[[2]](#references)</sup>

Việc triage tĩnh và runtime có thể nhanh chóng xác định các ranh giới này.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

Trong một bài kiểm thử được ủy quyền, hãy chặn yêu cầu kiểm tra cập nhật, lưu trữ mọi phản hồi và thay đổi từng trường một. Sau đó, kiểm tra quyền sở hữu/quyền truy cập của thư mục staging và theo dõi các lần mở tệp từ lúc tải xuống đến khi cài đặt. Trên macOS, tiếp tục với [kiểm thử ranh giới tin cậy của trình cài đặt](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) nếu luồng xử lý chuyển đến helper có đặc quyền, và xem xét [các điểm yếu của code-signing](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md) thay vì coi “đã ký” là bước kiểm tra danh tính hoàn chỉnh.<sup>[[2]](#references)</sup>

### Ràng buộc và chính sách dự kiến

Một thiết kế có thể bảo vệ được sẽ xác thực cả metadata lựa chọn lẫn byte của artifact. Thiết kế tham chiếu SafeUpdater minh họa public key Ed25519 được nhúng, manifest và artifact được ký, thông điệp đã ký được tạo từ `SHA-256(file)` cùng phiên bản, và digest SHA-512 của artifact được lưu trong metadata đã ký; đây rõ ràng là tài liệu tham khảo nghiên cứu, không phải package sẵn sàng cho môi trường production.<sup>[[1]](#references)[[2]](#references)</sup>

Hãy xác minh rằng mục tiêu cũng cung cấp các thuộc tính sau.<sup>[[1]](#references)[[2]](#references)</sup>

- sử dụng biểu diễn đã ký không mơ hồ, ràng buộc digest của artifact với phiên bản chuẩn hóa và môi trường phát hành;
- mặc định vô hiệu hóa việc hạ cấp và thực thi phiên bản tối thiểu được chấp nhận cho rollback được ủy quyền;
- tách biệt production với non-production bằng các key/channel riêng hoặc dữ liệu chính sách phát hành đã được xác thực; và
- cài đặt tệp đã mở được xác minh (hoặc handle/object bất biến tương đương) thay vì phân giải lại cùng pathname.

## References

- [1] [Bản triển khai tham chiếu ElectronSafeUpdater của Doyensec](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: Thiết kế cơ chế tự động cập nhật Electron an toàn](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
