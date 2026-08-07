# Handlers za app za File Extension na URL scheme za macOS

{{#include ../../banners/hacktricks-training.md}}

## Database ya LaunchServices

Hii ni database ya applications zote zilizosakinishwa kwenye macOS ambayo inaweza kuulizwa ili kupata taarifa kuhusu kila application iliyosakinishwa, kama vile **URL schemes**, **document types**, **UTIs**, na handlers chaguomsingi.

Inawezekana kutupa database hii kwa:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Au kutumia tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ndiyo kiini cha database. Inatoa **several XPC services** kama vile `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, na nyinginezo. Lakini pia **requires some entitlements** kwa applications ili ziweze kutumia XPC functionalities zilizo exposed, kama vile `.launchservices.changedefaulthandler` au `.launchservices.changeurlschemehandler` kubadilisha default apps za MIME types au URL schemes, pamoja na nyinginezo.

**`/System/Library/CoreServices/launchservicesd`** hudai service `com.apple.coreservices.launchservicesd` na inaweza kuulizwa ili kupata taarifa kuhusu applications zinazoendesha. Inaweza kuulizwa kwa kutumia system tool **`/usr/bin/lsappinfo`** au kupitia [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Kwa mtazamo wa operator, zingatia kwamba kwa kawaida kuna **two useful views**:

- **registration database** inayosimamiwa na LaunchServices / `lsd` (inayohifadhiwa kwenye files za `.csstore`).
- **per-user effective defaults** zinazohifadhiwa katika `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` ndani ya array ya `LSHandlers`.

Tofauti hii ni muhimu: application inaweza kuwa **registered** kuwa na uwezo wa kushughulikia type au scheme fulani, lakini **current default** bado inaweza kuwa bundle ID nyingine.

## File Extension & URL scheme app handlers

Mstari ufuatao unaweza kuwa muhimu katika kutafuta applications zinazoweza kufungua files kulingana na extension:
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
Unaweza pia kuangalia viendelezi vinavyoungwa mkono na application kwa kufanya:
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

Faili muhimu zaidi kwa **chaguo-msingi za mtumiaji wa sasa** kwa kawaida ni:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Ili kudump **URL scheme** handlers kutoka humo:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Ili kudump handlers za **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Ili kutatua mti wa UTI wa faili ya sampuli:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Ikiwa unataka CLI iliyo rahisi zaidi kutumia ili kuuliza au kubadilisha chaguomsingi:
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
## Vifunguo vya kuvutia vya Info.plist

Wakati wa kufanya triage ya application bundle, vifunguo hivi vina umuhimu mkubwa zaidi:

- **`CFBundleDocumentTypes`**: makundi ya document ambayo bundle inadai inaweza kufungua.
- **`LSItemContentTypes`**: njia **ya kisasa / inayopendelewa** ya kuhusisha document types na UTIs.
- **`LSHandlerRank`**: ranking inayotumiwa na LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes zinazotekelezwa na app.
- **`UTExportedTypeDeclarations`**: UTIs ambazo app **inamiliki**.
- **`UTImportedTypeDeclarations`**: UTIs ambazo app haimiliki lakini inataka mfumo uzitambue.

Command muhimu ya kufanya triage haraka ni:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Maelezo mafupi lakini muhimu: ikiwa **`LSItemContentTypes`** ipo, keys za zamani kama **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, na **`CFBundleTypeOSTypes`** kimsingi ni data za legacy compatibility. Kwa handler resolution halisi, zingatia kwanza njia ya UTI.

## Maelezo ya Offensive

Applications hazihitaji kuendeshwa ili ziwe muhimu. `.app` bundle iliyowekwa au kunakiliwa inaweza **kuchanganuliwa automatically na `lsd` mara tu inapoandikwa kwenye disk**, na document types / URL schemes ilizotangaza zinaweza kusajiliwa bila user kuwahi ku-launch bundle hiyo.

Hii ni muhimu kwa **persistence / hijacking research** na pia kwa **initial-access chains**:

- App hasidi inaweza kudai **rare extension** au **custom UTI** na kusubiri victim afungue lure file.
- App hasidi inaweza kusajili **custom URL scheme** inayoweza kufikiwa kutoka kwa browser, Electron app, office document, chat client, au helper app nyingine.<sup>[[1]](#references)</sup>
- Ukihariri app bundle baada ya kuijenga, unaweza kulazimisha LaunchServices iichanganue tena kwa:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Wakati wa kujaribu bundles zinazotiliwa shaka, zingatia hasa:

- **`LSHandlerRank=Owner`** kwenye aina zisizo za kawaida.
- Arrays pana za **`CFBundleDocumentTypes`** zinazodai extensions nyingi.
- **Helper / wrapper apps** ambazo tabia yake pekee ya kuvutia imefichwa nyuma ya document au URI handler.
- Mafaili yanayofanana na shortcuts (`.webloc`, `.inetloc`, `.fileloc`) ambayo huishia kuelekezwa kwenye LaunchServices. Kwa hila za aina ya `.fileloc` na vipengele vinavyohusiana na Gatekeeper, angalia [ukurasa huu mwingine](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Ikiwa lengo lako ni kupata passive code-execution kwa kuvinjari folda tu au kuchagua faili, pia angalia ukurasa maalum wa [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), kwa kuwa hiyo ni file-handler surface tofauti lakini inayohusiana kwa karibu.

## Marejeo


- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
