# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

This is a database of all the installed applications in macOS that can be queried to get information about each installed application such as supported **URL schemes**, **document types**, **UTIs**, and default handlers.

It's possible to dump this database with:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Or using the tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** is the brain of the database. It provides **several XPC services** like `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, and more. But it also **requires some entitlements** to applications to be able to use the exposed XPC functionalities, like `.launchservices.changedefaulthandler` or `.launchservices.changeurlschemehandler` to change default apps for MIME types or URL schemes and others.

**`/System/Library/CoreServices/launchservicesd`** claims the service `com.apple.coreservices.launchservicesd` and can be queried to get information about running applications. It can be queried with the system tool **`/usr/bin/lsappinfo`** or with [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

From an operator perspective, keep in mind there are usually **two useful views**:

- The **registration database** managed by LaunchServices / `lsd` (backed by `.csstore` files).
- The **per-user effective defaults** stored in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` inside the `LSHandlers` array.

This distinction matters: an application can be **registered** as able to handle a type or scheme, but the **current default** may still be another bundle ID.

On recent macOS releases, registration discovery is not limited to `/Applications`: apps in other Spotlight-visible, accessible folders and mounted/shared volumes can enter the registry. Therefore, preserve the `path` and volume information from `lsregister -dump` during triage and do not assume that unregistering an app is durable while the bundle remains discoverable.<sup>[[4]](#references)</sup>

## File Extension & URL scheme app handlers

The following line can be useful to find the applications that can open files depending on the extension:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```

Or use something like [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):

```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```

You can also check the extensions supported by an application doing:

```bash
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
				<string>css</string>
				<string>pdf</string>
				<string>webarchive</string>
				<string>webbookmark</string>
				<string>webhistory</string>
				<string>webloc</string>
				<string>download</string>
				<string>safariextz</string>
				<string>gif</string>
				<string>html</string>
				<string>htm</string>
				<string>js</string>
				<string>jpg</string>
				<string>jpeg</string>
				<string>jp2</string>
				<string>txt</string>
				<string>text</string>
				<string>png</string>
				<string>tiff</string>
				<string>tif</string>
				<string>url</string>
				<string>ico</string>
				<string>xhtml</string>
				<string>xht</string>
				<string>xml</string>
				<string>xbl</string>
				<string>svg</string>
```

## Enumerating effective handlers

The most useful file for the **current user's defaults** is usually:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

To dump **URL scheme** handlers from it:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

To dump **content-type / UTI** handlers:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

To resolve the UTI tree of a sample file:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

If you want a friendlier CLI to query or change defaults:

```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```

### Per-file `Open With` overrides

Handler resolution also has a **file-specific** layer. Before falling back to the file's UTI and the user's global default, LaunchServices checks the `com.apple.LaunchServices.OpenWith` extended attribute. Finder creates it when **Always Open With** is selected for one file; its value is a binary property list containing an application path, bundle identifier, and version selector.<sup>[[3]](#references)</sup>

Inspect and decode it without trusting the filename extension:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

This is useful when a single lure opens with an unexpected application even though `duti`, `dutix`, or `LSHandlers` reports a benign global default. For a controlled lab, the exact opaque value can be copied from a file configured through Finder; deleting it restores normal type-based resolution:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Interesting Info.plist keys

When triaging an application bundle, these keys matter the most:

- **`CFBundleDocumentTypes`**: document groups the bundle claims it can open.
- **`LSItemContentTypes`**: the **modern / preferred** way to bind document types to UTIs.
- **`LSHandlerRank`**: ranking used by LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes implemented by the app.
- **`UTExportedTypeDeclarations`**: UTIs the app **owns**.
- **`UTImportedTypeDeclarations`**: UTIs the app doesn't own but wants the system to recognize.

A useful quick triage command is:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

A subtle but important detail: if **`LSItemContentTypes`** is present, older keys such as **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, and **`CFBundleTypeOSTypes`** are effectively legacy compatibility data. For actual handler resolution, focus on the UTI path first.

## Offensive notes

Applications do not need to run before their handler claims become interesting, but **writing a `.app` bundle alone does not guarantee immediate registration**. Finder can register an app when it discovers it, including when a user browses its folder; registration can also occur at boot or login or through an explicit registration call. Check `lsregister -dump` before testing a claim. Registration alone neither launches the app nor makes it the effective default.<sup>[[5]](#references)</sup> For the persistence prerequisites, see [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

This is useful both for **persistence / hijacking research** and for **initial-access chains**:

- A malicious app can claim a **rare extension** or a **custom UTI** and wait for the victim to open the lure file.
- A malicious app can register a **custom URL scheme** reachable from a browser, Electron app, office document, chat client, or another helper app.<sup>[[1]](#references)</sup>
- To separate normal default resolution from testing a particular candidate handler, invoke the scheme through LaunchServices with `open 'targetscheme://host/path?value=test'`, then target a specific registered bundle with `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. This is useful for auditing how the receiving app validates and decodes attacker-controlled URL components.<sup>[[1]](#references)</sup>
- If you edit an app bundle after building it, you can force LaunchServices to re-parse it with:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

When testing suspicious bundles, pay special attention to:

- **`LSHandlerRank=Owner`** on uncommon types.
- **Broad `CFBundleDocumentTypes`** arrays claiming many extensions.
- **Helper / wrapper apps** whose only interesting behavior is behind a document or URI handler.
- **Shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`) that end up dispatching into LaunchServices. For `.fileloc`-style tricks and related Gatekeeper angles, check [this other page](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### URL parameters forwarded into downstream options

A browser's external-protocol confirmation only approves opening the handler; it does not make the URL parameters trustworthy. Trace the receiving app's URL parser into any library, media engine, helper process, or file-writing option. Look for a query-key prefix that turns URL fields into downstream option names. Test both literal and percent-encoded separators with a harmless marker in a disposable account.<sup>[[6]](#references)</sup>

Verify the **final option accepted by the downstream component**, not just the app's initial parsing. One handler allowed prefixed query keys to reach mpv input commands; blocking that option still left a file-write route. Test the reachable option class, not only one known-dangerous key.<sup>[[7]](#references)</sup>

### Built-in `applescript://` handler

The `applescript://com.apple.scripteditor` URL handler accepts `action=new` and a URL-encoded `script` parameter. A browser link can therefore open Script Editor with attacker-controlled AppleScript already in the editor, avoiding a Terminal paste step. This is **not automatic execution**: the browser may ask to open Script Editor, and the user must run the script.<sup>[[8]](#references)</sup>

Recent macOS versions can add a script-document warning, while XProtect scans AppleScript at execution.<sup>[[8]](#references)[[9]](#references)</sup>

Use a harmless local probe to check the handler and prompts on the macOS release being assessed; it should only populate the editor until **Run** is clicked.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

If your goal is passive code-execution from merely browsing to a folder or selecting a file, also check the dedicated page for [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), as that is a different but closely related file-handler surface.



## References

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - How macOS opens a file in the correct app](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Controlling LaunchServices in macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Launch Services Concepts](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - IINA URL scheme command execution research](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Unsafe handling of mpv options in its URL scheme](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - ClickFix technique uses Script Editor instead of Terminal](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Terminal and script protections](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
