# Αποσφαλμάτωση του Default Sandbox του macOS

{{#include ../../../../banners/hacktricks-training.md}}

Αυτή η σελίδα δημιουργεί έναν μικρό command runner και τον υπογράφει με το entitlement macOS App Sandbox. Οι εντολές που εκκινούνται με `system()` κληρονομούν τους περιορισμούς του sandbox της εφαρμογής, επομένως αυτό είναι χρήσιμο για τη δοκιμή συμπεριφοράς μέσα σε ένα sandbox· δεν αποτελεί sandbox escape.<sup>[[1]](#references)</sup>

1. Κάντε compile την εφαρμογή:
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
Μεταγλωττίστε το με:
```bash
clang -framework Foundation -o SandboxedShellApp main.m
```
2. Δημιουργήστε το bundle `.app`:
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
3. Ορίστε τα entitlements. Η δεύτερη παραλλαγή παρέχει επίσης πρόσβαση ανάγνωσης/εγγραφής στον φάκελο Downloads του χρήστη.<sup>[[2]](#references)</sup>

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

4. Υπογράψτε την εφαρμογή με μια signing identity διαθέσιμη στο keychain και, στη συνέχεια, εκτελέστε την. Κατά τη μη αυτόματη υπογραφή, το `codesign --entitlements` ενσωματώνει τη λίστα ιδιοτήτων entitlement στην υπογραφή της εφαρμογής.<sup>[[1]](#references)</sup>
```bash
codesign --entitlements entitlements.plist -s "YourIdentity" SandboxedShellApp.app
./SandboxedShellApp.app/Contents/MacOS/SandboxedShellApp

# Remove the signature if it is no longer needed.
codesign --remove-signature SandboxedShellApp.app
```
## References

- [1] [Apple Code Signing Guide: Προσθήκη Entitlements για Sandboxing χειροκίνητα](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW31)
- [2] [Apple: `com.apple.security.files.downloads.read-write` entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.files.downloads.read-write)
{{#include ../../../../banners/hacktricks-training.md}}
