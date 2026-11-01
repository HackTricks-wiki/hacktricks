# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Các Keychain chính

- **User Keychain** (`~/Library/Keychains/login.keychain-db`) được dùng để lưu **thông tin xác thực dành riêng cho người dùng**, chẳng hạn như mật khẩu ứng dụng, mật khẩu internet, chứng chỉ do người dùng tạo, mật khẩu mạng và khóa công khai/riêng tư do người dùng tạo.
- **System Keychain** (`/Library/Keychains/System.keychain`) lưu **thông tin xác thực trên toàn hệ thống**, chẳng hạn như mật khẩu WiFi, chứng chỉ root của hệ thống, khóa riêng tư của hệ thống và mật khẩu ứng dụng hệ thống.<sup>[[1]](#references)</sup>
  - Có thể tìm thấy các thành phần khác như chứng chỉ trong `/System/Library/Keychains/*`
- **Data protection keychain** của từng người dùng xuất hiện dưới dạng **Local Items** hoặc **iCloud** trong Keychain Access. Nó tách biệt với `login.keychain-db` và bao gồm cả mục chỉ lưu cục bộ lẫn mục có thể đồng bộ; `security` chủ yếu là công cụ dành cho file-based keychain, vì vậy kết quả `dump-keychain` ngắn không có nghĩa là không có thông tin xác thực ở đây.<sup>[[5]](#references)</sup>
- Trong **iOS** chỉ có một **Keychain**, nằm ở `/private/var/Keychains/`. Thư mục này cũng chứa các cơ sở dữ liệu cho `TrustStore`, cơ quan cấp chứng chỉ (`caissuercache`) và các mục OSCP (`ocspache`).
  - Ứng dụng chỉ được phép truy cập vùng riêng của chúng trong keychain, dựa trên application identifier.

### Truy cập Keychain bằng mật khẩu

Bản sao **file-based** keychain không ở dạng plaintext. Để giải mã ngoại tuyến các mục được bảo vệ, cần có mật khẩu keychain hoặc vật liệu khóa tương đương; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) hỗ trợ định dạng này.<sup>[[1]](#references)</sup> Điều này khác với việc đọc trực tiếp trong phiên người dùng đã mở khóa, khi các quyền kiểm soát truy cập của mục có thể cho phép đọc hoặc kích hoạt lời nhắc mà không cần nhập lại mật khẩu đăng nhập. Data protection keychain có mô hình bảo vệ và access-group khác.<sup>[[5]](#references)</sup>

## Cơ chế bảo vệ các mục Keychain

### ACL của file-based keychain

Các quy tắc `SecAccess` ACL và partition-list dưới đây mô tả **file-based** keychain. Thay vào đó, các mục trong data protection keychain sử dụng access group dựa trên code signing và các điều kiện `SecAccessControl` tùy chọn; không nên suy luận khả năng truy cập của chúng từ bản dump ACL của file-based keychain.<sup>[[5]](#references)</sup>

Mỗi mục trong file-based keychain được quản lý bởi **Access Control Lists (ACLs)**, quy định ai có thể thực hiện các hành động khác nhau trên mục keychain, bao gồm:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Cho phép người nắm giữ lấy được nội dung bí mật ở dạng văn bản thuần.
- **`kSecACLAuthorizationExportWrapped`**: Cho phép người nắm giữ lấy được nội dung bí mật đã mã hóa bằng một mật khẩu khác được cung cấp.
- **`kSecACLAuthorizationAny`**: Cho phép người nắm giữ thực hiện mọi hành động.

ACL còn đi kèm một **danh sách ứng dụng đáng tin cậy** có thể thực hiện các hành động này mà không cần lời nhắc. Danh sách này có thể là:<sup>[[1]](#references)</sup>

- **N`il`** (không cần cấp quyền, **mọi ứng dụng đều đáng tin cậy**)
- Danh sách **rỗng** (**không ứng dụng nào** được tin cậy)
- **Danh sách** các **ứng dụng** cụ thể.

Mục này cũng có thể chứa khóa **`kSecACLAuthorizationPartitionID`,** được dùng để xác định **teamid, apple** và **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Nếu chỉ định **teamid**, ứng dụng phải có **cùng teamid** để **truy cập** giá trị của mục **mà không** cần **lời nhắc**.
- Nếu chỉ định **apple**, ứng dụng phải được **Apple ký**.
- Nếu chỉ định **cdhash**, **ứng dụng** phải có **cdhash** cụ thể đó.

### Tạo mục trong file-based keychain

Khi tạo **mục** **mới** bằng **`Keychain Access.app`**, các quy tắc sau được áp dụng:<sup>[[1]](#references)</sup>

- Mọi ứng dụng đều có thể mã hóa.
- **Không ứng dụng nào** có thể xuất/giải mã (mà không nhắc người dùng).
- Mọi ứng dụng đều có thể xem phần kiểm tra tính toàn vẹn.
- Không ứng dụng nào có thể thay đổi ACL.
- **partitionID** được đặt thành **`apple`**.

Khi **một ứng dụng tạo mục trong keychain**, các quy tắc sẽ hơi khác:<sup>[[1]](#references)</sup>

- Mọi ứng dụng đều có thể mã hóa.
- Chỉ **ứng dụng tạo mục** (hoặc các ứng dụng khác được thêm rõ ràng) mới có thể xuất/giải mã (mà không nhắc người dùng).
- Mọi ứng dụng đều có thể xem phần kiểm tra tính toàn vẹn.
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

`-S` đặt danh sách partition của mục, còn `-k` cung cấp mật khẩu Keychain hiện tại cần thiết để thực hiện thay đổi đó; cờ nhận mật khẩu này đã bị deprecated.<sup>[[4]](#references)</sup> Cập nhật thành công không chứng minh rằng lần đọc sau sẽ không hiện lời nhắc: một prototype đã tắt được quan sát thấy vẫn kích hoạt lời nhắc xác nhận khi truy vấn mục thông qua `Security.framework`. Partition ID khớp chỉ là một phần trong các bước kiểm tra ACL và ứng dụng đáng tin cậy được mô tả ở trên, vì vậy hãy xác minh đường dẫn đọc thực tế.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> Có thể dùng công cụ [**LockSmith**](https://github.com/its-a-feature/LockSmith) để **liệt kê và dump các secret trong Keychain mà không tạo lời nhắc**
>
> Có thể tìm các endpoint API khác trong mã nguồn [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Liệt kê và lấy **thông tin** về từng mục Keychain bằng **Security Framework**, hoặc kiểm tra công cụ CLI mã nguồn mở của Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Một số ví dụ về API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** cung cấp thông tin về từng mục và có một số thuộc tính bạn có thể đặt khi dùng API này:
  - **`kSecReturnData`**: Nếu true, API sẽ thử giải mã dữ liệu (đặt thành false để tránh các cửa sổ bật lên có thể xuất hiện)
  - **`kSecReturnRef`**: Lấy tham chiếu đối tượng cho khóa, chứng chỉ hoặc danh tính; các mục mật khẩu không có dạng biểu diễn đối tượng này. Dùng `kSecReturnPersistentRef` để xác định một mật khẩu cho truy vấn có mục tiêu sau này.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: Lấy metadata về các mục
  - **`kSecMatchLimit`**: Số kết quả cần trả về
  - **`kSecClass`**: Loại mục Keychain

Lấy **ACL** của từng mục:<sup>[[1]](#references)</sup>

- Dùng API **`SecAccessCopyACLList`** để lấy **ACL của mục Keychain**. API này trả về một danh sách ACL (chẳng hạn `kSecACLAuthorizationExportClear` và các giá trị khác đã đề cập trước đó), trong đó mỗi mục có:<sup>[[1]](#references)[[2]](#references)</sup>
  - Mô tả
  - **Danh sách ứng dụng đáng tin cậy**. Danh sách này có thể gồm:
    - Một ứng dụng: /Applications/Slack.app
    - Một binary: /usr/libexec/airportd
    - Một group: group://AirPort

Xuất dữ liệu:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** lấy plaintext
- API **`SecItemExport`** xuất khóa và chứng chỉ, nhưng có thể cần đặt mật khẩu để xuất nội dung đã mã hóa

Sau đây là các **điều kiện** để có thể **xuất secret mà không hiện lời nhắc**:<sup>[[1]](#references)</sup>

- Nếu có **ít nhất 1 ứng dụng đáng tin cậy** được liệt kê:
  - Cần có **authorization** phù hợp (**`Nil`**, hoặc thuộc danh sách ứng dụng được phép trong authorization để truy cập thông tin secret)
  - Chữ ký code phải khớp với **PartitionID**
  - Chữ ký code phải khớp với chữ ký của một **ứng dụng đáng tin cậy** (hoặc thuộc KeychainAccessGroup phù hợp)
- Nếu **tất cả ứng dụng đều được tin cậy**:
  - Cần có **authorization** phù hợp
  - Chữ ký code phải khớp với **PartitionID**
    - Nếu **không có PartitionID**, thì không cần điều kiện này

> [!CAUTION]
> Vì vậy, nếu có **1 ứng dụng được liệt kê**, bạn cần **inject code vào ứng dụng đó**.
>
> Nếu **apple** được chỉ định trong **partitionID**, bạn có thể truy cập bằng **`osascript`**, áp dụng với mọi mục tin cậy tất cả ứng dụng có apple trong partitionID. Cũng có thể dùng **`Python`**.

### Hai thuộc tính bổ sung

- **Invisible**: Cờ boolean dùng để **ẩn** mục khỏi ứng dụng Keychain trong **UI**<sup>[[1]](#references)</sup>
- **General**: Dùng để lưu **metadata** (tức là KHÔNG ĐƯỢC MÃ HÓA)<sup>[[1]](#references)</sup>
  - Microsoft từng lưu ở dạng plaintext tất cả refresh token dùng để truy cập endpoint nhạy cảm.<sup>[[1]](#references)</sup>

### Data protection keychain: liệt kê, sau đó truy vấn một mục

Chạy `SecItemCopyMatching` từ một **ứng dụng đã ký trong ngữ cảnh đăng nhập của người dùng mục tiêu** với `kSecUseDataProtectionKeychain: true`; đừng cho rằng `security dump-keychain` hoặc truy vấn SecItem mặc định đã tìm trong kho này. Caller chỉ thấy các access group mà nó được phép truy cập.<sup>[[5]](#references)</sup>

Nếu mã kiểm thử chạy bên trong một process khác, quyền truy cập data protection keychain của nó tuân theo entitlements của executable host đó. Kiểm tra entitlements đã ký thực tế bằng `codesign -d --entitlements - /path/to/Target.app` và xem [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) để biết các bước kiểm tra liên quan.<sup>[[7]](#references)</sup>

Trước tiên, chỉ yêu cầu **attributes** cho một lớp mục. `kSecAttrSynchronizableAny` bao gồm cả kết quả khớp cục bộ lẫn kết quả đồng bộ hóa iCloud; bỏ qua thuộc tính này sẽ loại trừ các mục có đồng bộ hóa.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` tránh hiển thị giao diện xác thực trong quá trình liệt kê rộng, nhưng đổi lại sẽ bỏ qua các mục được bảo vệ.<sup>[[9]](#references)</sup> Nếu cần, hãy lặp lại với `kSecClassInternetPassword`.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

Đối với một lần đọc bí mật được cho phép, hãy tạo một truy vấn **mới**, giới hạn cho mục đã chọn (ví dụ: class, service và account), đặt `kSecReturnData: true` và `kSecMatchLimit: kSecMatchLimitOne`, đồng thời dự kiến có xác thực riêng cho từng mục hoặc nhận lỗi. Không kết hợp `kSecReturnData` với `kSecMatchLimitAll` đối với các mục mật khẩu.<sup>[[10]](#references)</sup> Kết quả `errSecItemNotFound` cũng có thể do chọn sai kho, bộ lọc đồng bộ hoặc thiếu entitlement access-group, chứ không nhất thiết có nghĩa là không tồn tại thông tin xác thực.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: "Bẻ khóa Keychain của macOS" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Phiên bản mới của phần mềm đánh cắp macOS MacSync nhắm vào những người đam mê crypto và nhà phát triển](https://securelist.com/macsync-new-version/121383/)
- [4] [Bản sao trang man security(1) của Apple](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Về các API và cách triển khai keychain trên Mac](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: Những điều cơ bản](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: Những cạm bẫy và phương pháp hay nhất](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Truy cập các mục Keychain bằng Face ID hoặc Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
