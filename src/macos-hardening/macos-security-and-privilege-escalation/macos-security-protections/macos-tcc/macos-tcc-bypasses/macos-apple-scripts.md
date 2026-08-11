# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript is an automation language that can send Apple Events to scriptable applications. With the relevant grants, malware can inject JavaScript into a scriptable browser tab or use System Events/Accessibility to click a permission dialog. Apple Events and Accessibility are distinct TCC services and generally require their respective user approvals.<sup>[[3]](#references)</sup>

```applescript
tell window 1 of process "SecurityAgent"
     click button "Always Allow" of group 1
end tell
```

The `abbeycode/AppleScripts` repository contains automation examples.<sup>[[7]](#references)</sup>\
Find more info about malware using applescripts [**here**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automation / TCC quirks

Apple Events approvals are **directional**: the prompt is for a **source process -> target process** pair. Once the user clicks **Allow**, future requests from the same source to the same target are allowed until the entry is reset. During testing, granting `Terminal -> Finder` or `Terminal -> System Events` once is enough to reuse the permission later without another popup.<sup>[[1]](#references)</sup>

```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```

This is especially relevant when the **target** is **Finder**, because Finder always has **Full Disk Access** even if it doesn't appear in the FDA UI. Therefore, any host that already has Automation over Finder can be used as an AppleScript/JXA proxy to access TCC-protected files.<sup>[[1]](#references)</sup> The generic Finder and System Events payloads are already documented in [the main TCC page](../README.md) and in [the Apple Events page](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` is only the most visible entry point. AppleScript and JXA can also execute from **Mach-O binaries** via **`NSAppleScript`** / **`OSAScript`**, which is useful both for evasion and for living inside a host that already has interesting TCC grants.<sup>[[2]](#references)</sup>

```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```

If you build a custom helper that sends Apple Events directly, giving it a **real app identity** makes testing and operations much more reliable. In practice this means embedding an `Info.plist` with `CFBundleIdentifier` and `NSAppleEventsUsageDescription`, signing the binary, and granting the `com.apple.security.automation.apple-events` entitlement. Otherwise the Apple Events prompt is frequently attributed to the **parent host** (for example `Terminal`) or the `NSAppleScript` execution just fails with confusing `-1750` / `errOSASystemError` errors.<sup>[[2]](#references)</sup>

AppleScripts can be saved in compiled form and ordinarily decompiled with `osadecompile`.

However, these scripts can also be **exported as "Read only"** (via the "Export..." option):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>

```
file mal.scpt
mal.scpt: AppleScript compiled
```

In that case `osadecompile` refuses to recover normal source, but the bytecode and Apple Event terminology can still be analyzed.

SentinelOne's run-only research describes how to recover structure despite that restriction. `applescript-disassembler` and `aevt_decompile` help inspect the compiled script and Apple Event data.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [How Offensive Actors Use AppleScript For Attacking macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Adventures in Reversing Malicious Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [abbeycode/AppleScripts examples](https://github.com/abbeycode/AppleScripts)

{{#include ../../../../../banners/hacktricks-training.md}}
