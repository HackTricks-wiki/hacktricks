# macOS Default Sandbox 调试

{{#include ../../../../banners/hacktricks-training.md}}

此页面构建一个小型 command runner，并使用 macOS App Sandbox entitlement 对其进行签名。使用 `system()` 启动的命令会继承应用的 sandbox 限制，因此这对于测试 sandbox 内的行为很有用；但它不是 sandbox escape。<sup>[[1]](#references)</sup>

1. 编译应用程序：
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
使用以下命令编译：
```bash
clang -framework Foundation -o SandboxedShellApp main.m
```
2. 构建 `.app` bundle：
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
3. 定义 entitlements。第二种变体还授予对用户 Downloads 文件夹的读写访问权限。<sup>[[2]](#references)</sup>

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

4. 使用 keychain 中可用的签名身份为 app 签名，然后运行它。手动签名时，`codesign --entitlements` 会将 entitlement property list 嵌入 app 的签名中。<sup>[[1]](#references)</sup>
```bash
codesign --entitlements entitlements.plist -s "YourIdentity" SandboxedShellApp.app
./SandboxedShellApp.app/Contents/MacOS/SandboxedShellApp

# Remove the signature if it is no longer needed.
codesign --remove-signature SandboxedShellApp.app
```
## References

- [1] [Apple Code Signing Guide: 手动为 Sandbox 添加 Entitlements](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW31)
- [2] [Apple: `com.apple.security.files.downloads.read-write` entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.files.downloads.read-write)
{{#include ../../../../banners/hacktricks-training.md}}
