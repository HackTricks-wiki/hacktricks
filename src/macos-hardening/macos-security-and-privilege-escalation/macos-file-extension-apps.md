# Handlers za viendelezi vya faili na URL scheme za macOS

{{#include ../../banners/hacktricks-training.md}}

## Hifadhidata ya LaunchServices

Hii ni hifadhidata ya application zote zilizosakinishwa kwenye macOS ambayo inaweza kuulizwa ili kupata taarifa kuhusu kila application iliyosakinishwa, kama vile **URL schemes**, **document types**, **UTIs**, na handlers chaguomsingi.

Inawezekana ku-dump hifadhidata hii kwa:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Au kutumia tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ndiyo kiini cha database. Inatoa **XPC services kadhaa** kama vile `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, na nyingine zaidi. Lakini pia **inahitajia entitlements fulani** kwa applications ili ziweze kutumia utendaji wa XPC uliowekwa wazi, kama vile `.launchservices.changedefaulthandler` au `.launchservices.changeurlschemehandler` kubadilisha apps chaguomsingi za MIME types au URL schemes, pamoja na nyingine.

**`/System/Library/CoreServices/launchservicesd`** inadai service `com.apple.coreservices.launchservicesd` na inaweza ku-queryiwa ili kupata taarifa kuhusu applications zinazoendeshwa. Inaweza ku-queryiwa kwa kutumia system tool **`/usr/bin/lsappinfo`** au [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Kwa mtazamo wa operator, kumbuka kwamba kwa kawaida kuna **views mbili muhimu**:

- **Registration database** inayosimamiwa na LaunchServices / `lsd` (inayotegemezwa na files za `.csstore`).
- **Defaults zinazotumika kwa kila user** zilizohifadhiwa katika `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` ndani ya array ya `LSHandlers`.

Tofauti hii ni muhimu: application inaweza kuwa **imesajiliwa** kuwa inaweza kushughulikia type au scheme fulani, lakini **default ya sasa** bado inaweza kuwa bundle ID nyingine.

## File Extension & URL scheme app handlers

Mstari ufuatao unaweza kuwa muhimu ili kupata applications zinazoweza kufungua files kulingana na extension:
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
Unaweza pia kuangalia viendelezi vinavyotumika na programu kwa kufanya:
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

Faili yenye manufaa zaidi kwa **defaults za mtumiaji wa sasa** kwa kawaida ni:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Ili kufanya dump ya **URL scheme** handlers kutoka humo:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Ili kudump **content-type / UTI** handlers:
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
## Key za kuvutia za Info.plist

Wakati wa kufanya triage ya application bundle, key hizi ndizo muhimu zaidi:

- **`CFBundleDocumentTypes`**: makundi ya hati ambayo bundle inadai inaweza kufungua.
- **`LSItemContentTypes`**: njia **ya kisasa / inayopendelewa** ya kuhusisha aina za hati na UTIs.
- **`LSHandlerRank`**: mpangilio wa ranking unaotumiwa na LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes zinazotekelezwa na app.
- **`UTExportedTypeDeclarations`**: UTIs ambazo app **inamiliki**.
- **`UTImportedTypeDeclarations`**: UTIs ambazo app haimiliki lakini inataka system izitambue.

Command muhimu ya kufanya triage kwa haraka ni:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Maelezo madogo lakini muhimu: ikiwa **`LSItemContentTypes`** ipo, keys za zamani kama **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, na **`CFBundleTypeOSTypes`** kwa vitendo ni data za legacy compatibility. Kwa ajili ya handler resolution halisi, anza na njia ya UTI.

## Offensive notes

Applications hazihitaji ku-execute ili ziwe muhimu. `.app` bundle iliyodropped au ku-clone inaweza **ku-parsewa automatically na `lsd` mara tu inapoandikwa kwenye disk**, na document types / URL schemes ilizotangaza zinaweza kusajiliwa bila mtumiaji kuwahi ku-launch bundle hiyo.

Hii ni muhimu kwa **persistence / hijacking research** na pia kwa **initial-access chains**:

- App hasidi inaweza kudai **rare extension** au **custom UTI**, kisha kusubiri victim afungue lure file.
- App hasidi inaweza kusajili **custom URL scheme** inayoweza kufikiwa kutoka kwa browser, Electron app, office document, chat client, au helper app nyingine.<sup>[[1]](#references)</sup>
- Ukihariri app bundle baada ya kuijenga, unaweza kuilazimisha LaunchServices i-parse tena kwa kutumia:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Unapopojaribu bundles zenye mashaka, zingatia hasa:

- **`LSHandlerRank=Owner`** kwenye types zisizo za kawaida.
- Arrays pana za **`CFBundleDocumentTypes`** zinazodai extensions nyingi.
- Apps za **helper / wrapper** ambazo tabia yake pekee ya kuvutia iko nyuma ya document au URI handler.
- Files zinazofanana na shortcuts (`.webloc`, `.inetloc`, `.fileloc`) ambazo huishia kutumwa kwa LaunchServices. Kwa mbinu za aina ya `.fileloc` na mikakati inayohusiana na Gatekeeper, angalia [this other page](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Ikiwa lengo lako ni code-execution ya kimya kwa kuvinjari tu folder au kuchagua file, pia angalia ukurasa maalum wa [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), kwa kuwa hiyo ni file-handler surface tofauti lakini inayohusiana kwa karibu.

## Marejeo

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
