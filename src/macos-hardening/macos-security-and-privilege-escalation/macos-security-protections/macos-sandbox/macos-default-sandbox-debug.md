# Gỡ lỗi Sandbox mặc định của macOS

{{#include ../../../../banners/hacktricks-training.md}}

Trang này tạo một trình chạy lệnh nhỏ và ký ứng dụng bằng entitlement App Sandbox của macOS. Các lệnh được khởi chạy bằng `system()` kế thừa các hạn chế sandbox của ứng dụng, vì vậy công cụ này hữu ích để kiểm tra hành vi bên trong sandbox; đây không phải là cách thoát sandbox.<sup>[[1]](#references)</sup>

1. Biên dịch ứng dụng:

```objectivec:main.m
#include <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        while (1) {
            char input[512];

            printf("Enter command to run (or 'exit' to quit): ");
            if (fgets(input, sizeof(input), stdin) == NULL) {
                break;
            }

            // Remove the trailing newline.
            size_t len = strlen(input);
            if (len > 0 && input[len - 1] == '\n') {
                input[len - 1] = '\0';
            }

            if (strcmp(input, "exit") == 0) {
                break;
            }

            system(input);
        }
    }
    return 0;
}
```

Biên dịch nó bằng:

```bash
clang -framework Foundation -o SandboxedShellApp main.m
```

2. Tạo bundle `.app`:

```bash
mkdir -p SandboxedShellApp.app/Contents/MacOS
mv SandboxedShellApp SandboxedShellApp.app/Contents/MacOS/

cat << EOF > SandboxedShellApp.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.SandboxedShellApp</string>
    <key>CFBundleName</key>
    <string>SandboxedShellApp</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleExecutable</key>
    <string>SandboxedShellApp</string>
</dict>
</plist>
EOF
```

3. Xác định các quyền. Biến thể thứ hai cũng cấp quyền truy cập đọc/ghi vào thư mục Downloads của người dùng.<sup>[[2]](#references)</sup>

{{#tabs}}
{{#tab name="sandbox"}}

```bash
cat << EOF > entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
</dict>
</plist>
EOF
```

{{#endtab}}

{{#tab name="sandbox + downloads"}}

```bash
cat << EOF > entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.files.downloads.read-write</key>
    <true/>
</dict>
</plist>
EOF
```

{{#endtab}}
{{#endtabs}}

4. Ký ứng dụng bằng danh tính ký có sẵn trong keychain, sau đó chạy ứng dụng. Khi ký thủ công, `codesign --entitlements` nhúng danh sách thuộc tính entitlement vào chữ ký của ứng dụng.<sup>[[1]](#references)</sup>

```bash
codesign --entitlements entitlements.plist -s "YourIdentity" SandboxedShellApp.app
./SandboxedShellApp.app/Contents/MacOS/SandboxedShellApp

# Remove the signature if it is no longer needed.
codesign --remove-signature SandboxedShellApp.app
```

## References

- [1] [Hướng dẫn ký mã của Apple: Thêm entitlement để sandboxing theo cách thủ công](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW31)
- [2] [Apple: entitlement `com.apple.security.files.downloads.read-write`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.files.downloads.read-write)
{{#include ../../../../banners/hacktricks-training.md}}
