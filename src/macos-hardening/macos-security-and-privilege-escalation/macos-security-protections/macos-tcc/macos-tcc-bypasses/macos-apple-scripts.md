# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

It's a scripting language used for task automation **interacting with remote processes**. It makes pretty easy to **ask other processes to perform some actions**. **Malware** may abuse these features to abuse functions exported by other processes.\
For example, a malware could **inject arbitrary JS code in browser opened pages**. Or **auto click** some allow permissions requested to the user;

```applescript
tell window 1 of process "SecurityAgent"
     click button "Always Allow" of group 1
end tell
```

Here you have some examples: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Find more info about malware using applescripts [**here**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

Apple Events approvals are **directional**: the prompt is for a **source process -> target process** pair. Once the user clicks **Allow**, future requests from the same source to the same target are allowed until the entry is reset. During testing, granting `Terminal -> Finder` or `Terminal -> System Events` once is enough to reuse the permission later without another popup.

```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```

This is especially relevant when the **target** is **Finder**, because Finder always has **Full Disk Access** even if it doesn't appear in the FDA UI. Therefore, any host that already has Automation over Finder can be used as an AppleScript/JXA proxy to access TCC-protected files. The generic Finder and System Events payloads are already documented in [the main TCC page](../README.md) and in [the Apple Events page](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` is only the most visible entry point. AppleScript and JXA can also execute from **Mach-O binaries** via **`NSAppleScript`** / **`OSAScript`**, which is useful both for evasion and for living inside a host that already has interesting TCC grants.

```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```

If you build a custom helper that sends Apple Events directly, giving it a **real app identity** makes testing and operations much more reliable. In practice this means embedding an `Info.plist` with `CFBundleIdentifier` and `NSAppleEventsUsageDescription`, signing the binary, and granting the `com.apple.security.automation.apple-events` entitlement. Otherwise the Apple Events prompt is frequently attributed to the **parent host** (for example `Terminal`) or the `NSAppleScript` execution just fails with confusing `-1750` / `errOSASystemError` errors.

Apple scripts may be easily "**compiled**". These versions can be easily "**decompiled**" with `osadecompile`

However, these scripts can also be **exported as "Read only"** (via the "Export..." option):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>

```
file mal.scpt
mal.scpt: AppleScript compiled
```

and in this case the content cannot be decompiled even with `osadecompile`

However, there are still some tools that can be used to understand this kind of executables, [**read this research for more info**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). The tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) with [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) will be very useful to understand how the script works.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}


