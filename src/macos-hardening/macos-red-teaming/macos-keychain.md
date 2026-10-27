# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Các Keychain chính

- **User Keychain** (`~/Library/Keychains/login.keychain-db`) được dùng để lưu trữ **thông tin xác thực dành riêng cho người dùng** như mật khẩu ứng dụng, mật khẩu Internet, chứng chỉ do người dùng tạo, mật khẩu mạng và khóa công khai/riêng tư do người dùng tạo.
- **System Keychain** (`/Library/Keychains/System.keychain`) lưu trữ **thông tin xác thực trên toàn hệ thống** như mật khẩu WiFi, chứng chỉ gốc của hệ thống, khóa riêng tư của hệ thống và mật khẩu ứng dụng hệ thống.<sup>[[1]](#references)</sup>
  - Có thể tìm thấy các thành phần khác như chứng chỉ trong `/System/Library/Keychains/*`
- Trong **iOS**, chỉ có một **Keychain** nằm tại `/private/var/Keychains/`. Thư mục này cũng chứa các cơ sở dữ liệu cho `TrustStore`, cơ quan cấp chứng chỉ (`caissuercache`) và các mục OSCP (`ocspache`).
  - Các ứng dụng chỉ được phép truy cập khu vực riêng của mình trong keychain, dựa trên mã định danh ứng dụng.

### Truy cập Keychain bằng mật khẩu

Các tệp này tuy không có cơ chế bảo vệ sẵn và có thể **được tải xuống**, nhưng đã được mã hóa và cần **mật khẩu dạng văn bản thuần của người dùng để giải mã**. Có thể dùng công cụ như [**Chainbreaker**](https://github.com/n0fate/chainbreaker) để giải mã.<sup>[[1]](#references)</sup>

## Cơ chế bảo vệ các mục Keychain

### ACL

Mỗi mục trong keychain được kiểm soát bằng **Access Control Lists (ACL)**, quy định ai có thể thực hiện những hành động nào trên mục đó, bao gồm:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Cho phép người sở hữu lấy được nội dung bí mật ở dạng văn bản thuần.
- **`kSecACLAuthorizationExportWrapped`**: Cho phép người sở hữu lấy được nội dung bí mật đã mã hóa bằng một mật khẩu khác được cung cấp.
- **`kSecACLAuthorizationAny`**: Cho phép người sở hữu thực hiện bất kỳ hành động nào.

ACL còn đi kèm **danh sách các ứng dụng đáng tin cậy** có thể thực hiện những hành động này mà không cần hỏi. Danh sách có thể là:<sup>[[1]](#references)</sup>

- **N`il`** (không cần xác thực, **mọi người đều đáng tin cậy**)
- Danh sách **rỗng** (**không ai** được tin cậy)
- **Danh sách** các **ứng dụng** cụ thể.

Mục này cũng có thể chứa khóa **`kSecACLAuthorizationPartitionID`,** dùng để xác định **teamid, apple** và **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Nếu có chỉ định **teamid**, ứng dụng phải có **cùng teamid** để **truy cập** giá trị **mục** mà **không cần** hiển thị **lời nhắc**.
- Nếu có chỉ định **apple**, ứng dụng phải được **Apple** **ký**.
- Nếu có chỉ định **cdhash**, **ứng dụng** phải có **cdhash** cụ thể đó.

### Tạo mục Keychain

Khi tạo **mục** **mới** bằng **`Keychain Access.app`**, các quy tắc sau được áp dụng:<sup>[[1]](#references)</sup>

- Mọi ứng dụng đều có thể mã hóa.
- **Không ứng dụng nào** có thể xuất/giải mã (mà không hỏi người dùng).
- Mọi ứng dụng đều có thể xem thông tin kiểm tra tính toàn vẹn.
- Không ứng dụng nào có thể thay đổi ACL.
- **partitionID** được đặt thành **`apple`**.

Khi **một ứng dụng tạo mục trong keychain**, các quy tắc có đôi chút khác biệt:<sup>[[1]](#references)</sup>

- Mọi ứng dụng đều có thể mã hóa.
- Chỉ **ứng dụng tạo mục** (hoặc các ứng dụng khác được thêm rõ ràng) mới có thể xuất/giải mã (mà không hỏi người dùng).
- Mọi ứng dụng đều có thể xem thông tin kiểm tra tính toàn vẹn.
- Không ứng dụng nào có thể thay đổi ACL.
- **partitionID** được đặt thành **`teamid:[teamID here]`**.

## Truy cập Keychain

### `security`

```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` đặt danh sách partition của mục, còn `-k` cung cấp mật khẩu Keychain hiện tại cần thiết để thực hiện thay đổi đó; cờ nhận mật khẩu đã bị deprecated.<sup>[[4]](#references)</sup> Cập nhật thành công không chứng minh rằng lần đọc sau sẽ không hiện thông báo: một prototype đã tắt được quan sát thấy vẫn kích hoạt lời nhắc xác nhận khi truy vấn mục thông qua `Security.framework`. Partition ID khớp chỉ là một phần trong các bước kiểm tra ACL và ứng dụng đáng tin cậy đã mô tả ở trên, vì vậy hãy xác minh đường dẫn đọc thực tế.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> Có thể dùng công cụ [**LockSmith**](https://github.com/its-a-feature/LockSmith) để **liệt kê và dump Keychain** các secret mà **không tạo lời nhắc**
>
> Có thể tìm thấy các endpoint API khác trong mã nguồn [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Liệt kê và lấy **thông tin** về từng mục Keychain bằng **Security Framework**, hoặc bạn cũng có thể kiểm tra công cụ CLI mã nguồn mở [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Một số ví dụ API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** cung cấp thông tin về từng mục và có một số thuộc tính bạn có thể đặt khi sử dụng:
  - **`kSecReturnData`**: Nếu là true, API sẽ thử giải mã dữ liệu (đặt thành false để tránh khả năng xuất hiện pop-up)
  - **`kSecReturnRef`**: Lấy thêm tham chiếu đến mục Keychain (đặt thành true nếu sau này bạn thấy có thể giải mã mà không hiện pop-up)
  - **`kSecReturnAttributes`**: Lấy metadata về các mục
  - **`kSecMatchLimit`**: Số lượng kết quả trả về
  - **`kSecClass`**: Loại mục Keychain

Lấy **ACL** của từng mục:<sup>[[1]](#references)</sup>

- Dùng API **`SecAccessCopyACLList`** để lấy **ACL của mục Keychain**. API này trả về danh sách ACL (chẳng hạn như `kSecACLAuthorizationExportClear` và các ACL khác đã đề cập trước đó), trong đó mỗi mục có:<sup>[[1]](#references)[[2]](#references)</sup>
  - Mô tả
  - **Danh sách ứng dụng đáng tin cậy**. Có thể là:
    - Một ứng dụng: /Applications/Slack.app
    - Một binary: /usr/libexec/airportd
    - Một nhóm: group://AirPort

Xuất dữ liệu:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** lấy dữ liệu plaintext
- API **`SecItemExport`** xuất key và certificate, nhưng có thể cần đặt mật khẩu để xuất nội dung đã mã hóa

Và đây là các **điều kiện** để có thể **xuất secret mà không hiện lời nhắc**:<sup>[[1]](#references)</sup>

- Nếu có ít nhất một ứng dụng đáng tin cậy được liệt kê:
  - Cần có **quyền** phù hợp (**`Nil`**, hoặc nằm trong danh sách ứng dụng được phép trong quyền truy cập thông tin secret)
  - Chữ ký code cần khớp với **PartitionID**
  - Chữ ký code cần khớp với chữ ký của một **ứng dụng đáng tin cậy** (hoặc thuộc KeychainAccessGroup phù hợp)
- Nếu tất cả ứng dụng đều đáng tin cậy:
  - Cần có **quyền** phù hợp
  - Chữ ký code cần khớp với **PartitionID**
    - Nếu không có **PartitionID**, thì không cần điều này

> [!CAUTION]
> Vì vậy, nếu có **1 ứng dụng được liệt kê**, bạn cần **inject code vào ứng dụng đó**.
>
> Nếu **apple** được chỉ định trong **partitionID**, bạn có thể truy cập bằng **`osascript`** đối với mọi thứ tin cậy tất cả ứng dụng có apple trong partitionID. Cũng có thể dùng **`Python`**.

### Hai thuộc tính bổ sung

- **Invisible**: Cờ boolean dùng để **ẩn** mục khỏi ứng dụng Keychain trong **UI**<sup>[[1]](#references)</sup>
- **General**: Dùng để lưu **metadata** (do đó KHÔNG ĐƯỢC MÃ HÓA)<sup>[[1]](#references)</sup>
  - Microsoft từng lưu dưới dạng plaintext tất cả refresh token dùng để truy cập endpoint nhạy cảm.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: "Mở khóa macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Phiên bản mới của trình đánh cắp macOS MacSync nhắm đến những người đam mê tiền mã hóa và nhà phát triển](https://securelist.com/macsync-new-version/121383/)
- [4] [Bản sao trang man của Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
