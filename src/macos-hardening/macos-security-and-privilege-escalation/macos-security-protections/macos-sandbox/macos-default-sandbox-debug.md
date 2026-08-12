# Debug del Sandbox predefinito di macOS

{{#include ../../../../banners/hacktricks-training.md}}

Questa pagina crea un piccolo command runner e lo firma con l'entitlement macOS App Sandbox. I comandi avviati con `system()` ereditano le restrizioni del sandbox dell'app, quindi è utile per testare il comportamento all'interno di un sandbox; non è una sandbox escape.<sup>[[1]](#references)</sup>

1. Compila l'applicazione:
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
Compilalo con:
```bash
clang -framework Foundation -o SandboxedShellApp main.m
```
2. Crea il bundle `.app`:
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
3. Definisci gli entitlements. La seconda variante concede inoltre l'accesso in lettura/scrittura alla cartella Downloads dell'utente.<sup>[[2]](#references)</sup>

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

4. Firma l'app con un'identità di firma disponibile nel portachiavi, quindi eseguila. Quando si firma manualmente, `codesign --entitlements` incorpora il property list degli entitlement nella firma dell'app.<sup>[[1]](#references)</sup>
```bash
codesign --entitlements entitlements.plist -s "YourIdentity" SandboxedShellApp.app
./SandboxedShellApp.app/Contents/MacOS/SandboxedShellApp

# Remove the signature if it is no longer needed.
codesign --remove-signature SandboxedShellApp.app
```
## References

- [1] [Apple Code Signing Guide: Adding Entitlements for Sandboxing Manually](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW31)
- [2] [Apple: entitlement `com.apple.security.files.downloads.read-write`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.files.downloads.read-write)
{{#include ../../../../banners/hacktricks-training.md}}
