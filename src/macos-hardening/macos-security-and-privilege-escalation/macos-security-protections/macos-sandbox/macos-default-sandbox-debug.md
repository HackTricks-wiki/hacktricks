# Debugowanie domyślnego Sandbox w macOS

{{#include ../../../../banners/hacktricks-training.md}}

Ta strona tworzy mały runner poleceń i podpisuje go z uprawnieniem macOS App Sandbox. Polecenia uruchamiane za pomocą `system()` dziedziczą ograniczenia sandboxa aplikacji, dlatego jest to przydatne do testowania zachowania wewnątrz sandboxa; nie jest to sandbox escape.<sup>[[1]](#references)</sup>

1. Skompiluj aplikację:
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
Skompiluj to za pomocą:
```bash
clang -framework Foundation -o SandboxedShellApp main.m
```
2. Zbuduj bundle `.app`:
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
3. Zdefiniuj entitlements. Drugi wariant zapewnia również dostęp do odczytu/zapisu do folderu Downloads użytkownika.<sup>[[2]](#references)</sup>

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

4. Podpisz aplikację za pomocą tożsamości podpisywania dostępnej w keychain, a następnie ją uruchom. Podczas ręcznego podpisywania `codesign --entitlements` osadza listę właściwości entitlements w podpisie aplikacji.<sup>[[1]](#references)</sup>
```bash
codesign --entitlements entitlements.plist -s "YourIdentity" SandboxedShellApp.app
./SandboxedShellApp.app/Contents/MacOS/SandboxedShellApp

# Remove the signature if it is no longer needed.
codesign --remove-signature SandboxedShellApp.app
```
## References

- [1] [Apple Code Signing Guide: Ręczne dodawanie uprawnień dla Sandboxing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW31)
- [2] [Apple: uprawnienie `com.apple.security.files.downloads.read-write`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.files.downloads.read-write)
{{#include ../../../../banners/hacktricks-training.md}}
