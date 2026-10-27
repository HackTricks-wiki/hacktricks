# Kiểm tra tiến trình kết nối XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Kiểm tra tiến trình kết nối XPC

Khi một kết nối được thiết lập với dịch vụ XPC, máy chủ sẽ kiểm tra xem kết nối có được phép hay không. Thông thường, máy chủ sẽ thực hiện các bước kiểm tra sau:

1. Kiểm tra xem **tiến trình kết nối có được ký bằng** chứng chỉ do Apple ký hay không (chỉ Apple mới cấp loại chứng chỉ này).
   - Nếu **không xác minh điều này**, kẻ tấn công có thể tạo **chứng chỉ giả** để vượt qua mọi bước kiểm tra khác.
2. Kiểm tra xem tiến trình kết nối có được ký bằng **chứng chỉ của tổ chức** hay không (xác minh team ID).
   - Nếu **không xác minh điều này**, có thể dùng **bất kỳ chứng chỉ nhà phát triển nào** của Apple để ký và kết nối với dịch vụ.
3. Kiểm tra xem tiến trình kết nối có **bundle ID hợp lệ** hay không.
   - Nếu **không xác minh điều này**, có thể dùng bất kỳ công cụ nào **được cùng tổ chức ký** để tương tác với dịch vụ XPC.
4. (4 hoặc 5) Kiểm tra xem tiến trình kết nối có **số phiên bản phần mềm hợp lệ** hay không.
   - Nếu **không xác minh điều này**, một client cũ, không an toàn và dễ bị process injection có thể được dùng để kết nối với dịch vụ XPC ngay cả khi các bước kiểm tra khác đã được thực hiện.
5. (4 hoặc 5) Kiểm tra xem tiến trình kết nối có hardened runtime mà không có các entitlement nguy hiểm hay không (chẳng hạn entitlement cho phép tải các thư viện tùy ý hoặc sử dụng biến môi trường DYLD).
   1. Nếu **không xác minh điều này**, client có thể **dễ bị code injection**.
6. Kiểm tra xem tiến trình kết nối có **entitlement** cho phép kết nối với dịch vụ hay không. Điều này áp dụng cho các binary của Apple.
7. Việc **xác minh** phải **dựa trên** **audit token** của **client** kết nối, thay vì process ID (**PID**), vì audit token giúp ngăn chặn **PID reuse attacks**.
   - Các nhà phát triển **hiếm khi dùng** API gọi đến audit token vì API này là **private**, nên Apple có thể **thay đổi** bất kỳ lúc nào. Ngoài ra, ứng dụng trên Mac App Store không được phép sử dụng private API.
     - Nếu sử dụng phương thức **`processIdentifier`**, ứng dụng có thể dễ bị tấn công.
     - Nên dùng **`xpc_dictionary_get_audit_token`** thay vì **`xpc_connection_get_audit_token`**, vì phương thức sau cũng có thể [dễ bị tấn công trong một số trường hợp](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Tấn công giao tiếp

Để biết thêm thông tin về tấn công PID reuse, hãy xem:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Để biết thêm thông tin về tấn công **`xpc_connection_get_audit_token`**, hãy xem:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Ngăn chặn tấn công downgrade

Trustcache là một phương pháp phòng thủ được giới thiệu trên các máy Apple Silicon. Phương pháp này lưu trữ cơ sở dữ liệu CDHSAH của các binary Apple để chỉ những binary được cho phép và chưa bị chỉnh sửa mới có thể thực thi. Điều này ngăn chặn việc thực thi các phiên bản cũ hơn.

### Ví dụ mã

Máy chủ sẽ triển khai bước **xác minh** này trong một hàm có tên **`shouldAcceptNewConnection`**.

```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    //Check connection
    return YES;
}
```

Đối tượng `NSXPCConnection` có thuộc tính **`auditToken`** **riêng tư** (nên sử dụng thuộc tính này, mặc dù API riêng tư có thể thay đổi) và thuộc tính **`processIdentifier`** **công khai** (không nên dùng để xác thực).

Có thể xác minh tiến trình kết nối bằng cách như sau:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```

Nếu nhà phát triển không muốn kiểm tra phiên bản của client, ít nhất họ có thể kiểm tra xem client có dễ bị process injection hay không:

```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
    return Yes; // Accept connection
}
```

Các hằng số `cs_*` ở trên là các cờ code-signing được định nghĩa trong `osfmk/kern/cs_blobs.h` của XNU, vì vậy có thể đối chiếu chúng với mã nguồn thay vì phỏng đoán:<sup>[[4]](#references)</sup>

```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```

## References

- [1] [Apple Developer — Ngôn ngữ yêu cầu ký mã](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (các cờ ký mã `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
