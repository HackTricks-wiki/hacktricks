# Vishughulikiaji wa File Extension na URL scheme katika macOS

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Hii ni database ya applications zote zilizosakinishwa katika macOS, ambayo inaweza kuulizwa ili kupata taarifa kuhusu kila application iliyosakinishwa, kama vile **URL schemes** zinazotumika, **document types**, **UTIs**, na handlers chaguo-msingi.

Inawezekana kufanya dump ya database hii kwa kutumia:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Au kwa kutumia zana [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ndiyo ubongo wa database. Inatoa **XPC services kadhaa** kama vile `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, na nyingine. Lakini pia **inahitajia entitlements fulani** kutoka kwa applications ili ziweze kutumia utendaji wa XPC ulio wazi, kama vile `.launchservices.changedefaulthandler` au `.launchservices.changeurlschemehandler` ili kubadilisha apps za default za MIME types au URL schemes, pamoja na nyingine.

**`/System/Library/CoreServices/launchservicesd`** inadai service `com.apple.coreservices.launchservicesd` na inaweza kuulizwa ili kupata taarifa kuhusu applications zinazoendesha. Inaweza kuulizwa kwa kutumia system tool **`/usr/bin/lsappinfo`** au [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Kwa mtazamo wa operator, kumbuka kwamba kwa kawaida kuna **views mbili muhimu**:

- **Registration database** inayosimamiwa na LaunchServices / `lsd` (inayoungwa mkono na files za `.csstore`).
- **Defaults zinazotumika kwa kila user** zilizohifadhiwa katika `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` ndani ya array ya `LSHandlers`.

Tofauti hii ni muhimu: application inaweza kuwa **imesajiliwa** kuwa inaweza kushughulikia type au scheme fulani, lakini **default ya sasa** bado inaweza kuwa bundle ID nyingine.

## Vishughulikiaji vya app vya File Extension na URL scheme

Mstari ufuatao unaweza kuwa muhimu kwa kutafuta applications zinazoweza kufungua files kulingana na extension:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Au tumia kitu kama [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Unaweza pia kuangalia extensions zinazoungwa mkono na application kwa kufanya:
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
## Kuhesabu handlers zinazotumika

Faili muhimu zaidi kwa **defaults za mtumiaji wa sasa** kwa kawaida ni:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Ili kudump handlers za **URL scheme** kutoka humo:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Ili kuorodhesha handlers za **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Ili kutatua mti wa UTI wa faili ya sampuli:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Ikiwa unataka CLI iliyo rafiki zaidi ya kuuliza au kubadilisha mipangilio chaguomsingi:
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
## Info.plist keys Muhimu

Wakati wa kuchanganua application bundle, keys hizi ndizo muhimu zaidi:

- **`CFBundleDocumentTypes`**: makundi ya documents ambayo bundle inadai inaweza kufungua.
- **`LSItemContentTypes`**: njia **ya kisasa / inayopendelewa** ya kuhusisha document types na UTIs.
- **`LSHandlerRank`**: ranking inayotumiwa na LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes zinazotekelezwa na app.
- **`UTExportedTypeDeclarations`**: UTIs ambazo app **inamiliki**.
- **`UTImportedTypeDeclarations`**: UTIs ambazo app haimiliki lakini inataka system izitambue.

Command muhimu ya quick triage ni:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Maelezo madogo lakini muhimu: ikiwa **`LSItemContentTypes`** ipo, keys za zamani kama vile **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, na **`CFBundleTypeOSTypes`** kimsingi ni data za legacy compatibility. Kwa ajili ya handler resolution halisi, anza na njia ya UTI.

## Maelezo ya Offensive

Applications hazihitaji kuendeshwa ili ziwe muhimu. `.app` bundle iliyodondoshwa au kuigwa inaweza **kuchanganuliwa automatically na `lsd` mara tu inapoandikwa kwenye disk**, na document types / URL schemes ilizotangaza zinaweza kusajiliwa bila user kuwahi kuzindua bundle hiyo.

Hii ni muhimu kwa **utafiti wa persistence / hijacking** na pia kwa **initial-access chains**:

- App hasidi inaweza kudai **rare extension** au **custom UTI** na kusubiri victim afungue lure file.
- App hasidi inaweza kusajili **custom URL scheme** inayofikika kutoka kwenye browser, Electron app, office document, chat client, au helper app nyingine.<sup>[1]</sup>
- Ukihariri app bundle baada ya kuijenga, unaweza kulazimisha LaunchServices kuichanganua tena kwa:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Wakati wa kujaribu bundles zinazotia shaka, zingatia hasa:

- **`LSHandlerRank=Owner`** kwenye aina zisizo za kawaida.
- Arrays pana za **`CFBundleDocumentTypes`** zinazodai extensions nyingi.
- Apps za **Helper / wrapper** ambazo tabia yake pekee ya kuvutia imefichwa nyuma ya document au URI handler.
- Files zinazofanana na shortcuts (`.webloc`, `.inetloc`, `.fileloc`) ambazo hatimaye hutumwa kwa LaunchServices. Kwa mbinu za aina ya `.fileloc` na njia zinazohusiana za Gatekeeper, angalia [this other page](macos-security-protections/macos-fs-tricks/README.md).<sup>[2]</sup>

Ikiwa lengo lako ni code-execution isiyohitaji hatua kutoka kwa mtumiaji kwa kuvinjari tu folder au kuchagua file, pia angalia ukurasa maalum wa [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), kwa kuwa hiyo ni attack surface tofauti lakini inayohusiana kwa karibu ya file-handler.

## Marejeo

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
