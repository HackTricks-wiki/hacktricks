# macOS Default Sandbox Debug

{{#include ../../../../banners/hacktricks-training.md}}

이 페이지에서는 작은 command runner를 작성하고 macOS App Sandbox entitlement로 서명합니다. `system()`으로 실행된 명령은 앱의 sandbox 제한을 상속하므로, sandbox 내부의 동작을 테스트하는 데 유용합니다. 이는 sandbox escape가 아닙니다.<sup>[[1]](#references)</sup>

1. 애플리케이션을 컴파일합니다:
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
다음과 함께 컴파일하세요:
```bash
clang -framework Foundation -o SandboxedShellApp main.m
```
2. `.app` 번들 빌드:
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
3. entitlements를 정의합니다. 두 번째 변형은 사용자의 Downloads 폴더에 대한 읽기/쓰기 액세스 권한도 부여합니다.<sup>[[2]](#references)</sup>

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

4. keychain에서 사용할 수 있는 signing identity로 앱에 서명한 다음 실행합니다. 수동으로 서명할 때 `codesign --entitlements`는 entitlement property list를 앱의 서명에 포함합니다.<sup>[[1]](#references)</sup>
```bash
codesign --entitlements entitlements.plist -s "YourIdentity" SandboxedShellApp.app
./SandboxedShellApp.app/Contents/MacOS/SandboxedShellApp

# Remove the signature if it is no longer needed.
codesign --remove-signature SandboxedShellApp.app
```
## References

- [1] [Apple Code Signing Guide: Sandboxing을 위한 Entitlements 수동 추가](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW31)
- [2] [Apple: `com.apple.security.files.downloads.read-write` entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.files.downloads.read-write)
{{#include ../../../../banners/hacktricks-training.md}}
