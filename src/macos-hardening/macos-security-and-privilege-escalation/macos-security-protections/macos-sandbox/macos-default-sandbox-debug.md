# macOS Default Sandbox Debug

{{#include ../../../../banners/hacktricks-training.md}}

This page builds a small command runner and signs it with the macOS App Sandbox entitlement. Commands launched with `system()` inherit the app's sandbox restrictions, so this is useful for testing behavior inside a sandbox; it is not a sandbox escape.<sup>[[1]](#references)</sup>

1. Compile the application:

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

Compile it with:

```bash
clang -framework Foundation -o SandboxedShellApp main.m
```

2. Build the `.app` bundle:

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

3. Define the entitlements. The second variant also grants read/write access to the user's Downloads folder.<sup>[[2]](#references)</sup>

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

4. Sign the app with a signing identity available in the keychain, and then run it. When signing manually, `codesign --entitlements` embeds the entitlement property list in the app's signature.<sup>[[1]](#references)</sup>

```bash
codesign --entitlements entitlements.plist -s "YourIdentity" SandboxedShellApp.app
./SandboxedShellApp.app/Contents/MacOS/SandboxedShellApp

# Remove the signature if it is no longer needed.
codesign --remove-signature SandboxedShellApp.app
```

## References

- [1] [Apple Code Signing Guide: Adding Entitlements for Sandboxing Manually](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW31)
- [2] [Apple: `com.apple.security.files.downloads.read-write` entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.files.downloads.read-write)

{{#include ../../../../banners/hacktricks-training.md}}
