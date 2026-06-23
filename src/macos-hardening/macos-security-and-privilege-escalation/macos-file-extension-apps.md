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

Applications don't need to be executed to become interesting. A dropped or cloned `.app` bundle can be **parsed automatically by `lsd` as soon as it is written to disk**, and its declared document types / URL schemes may be registered without the user ever launching the bundle.

This is useful both for **persistence / hijacking research** and for **initial-access chains**:

- A malicious app can claim a **rare extension** or a **custom UTI** and wait for the victim to open the lure file.
- A malicious app can register a **custom URL scheme** reachable from a browser, Electron app, office document, chat client, or another helper app.
- If you edit an app bundle after building it, you can force LaunchServices to re-parse it with:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

When testing suspicious bundles, pay special attention to:

- **`LSHandlerRank=Owner`** on uncommon types.
- **Broad `CFBundleDocumentTypes`** arrays claiming many extensions.
- **Helper / wrapper apps** whose only interesting behavior is behind a document or URI handler.
- **Shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`) that end up dispatching into LaunchServices. For `.fileloc`-style tricks and related Gatekeeper angles, check [this other page](macos-security-protections/macos-fs-tricks/README.md).

If your goal is passive code-execution from merely browsing to a folder or selecting a file, also check the dedicated page for [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), as that is a different but closely related file-handler surface.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
