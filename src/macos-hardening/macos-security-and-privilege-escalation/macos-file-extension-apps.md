# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Hii ni hifadhidata ya programu zote zilizosakinishwa katika macOS ambazo zinaweza kuulizwa ili kupata taarifa kuhusu kila programu iliyosakinishwa kama vile **URL schemes** zinazotumika, **document types**, **UTIs**, na default handlers.

Inawezekana kutoa hifadhidata hii kwa:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Au kutumia zana [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ndio ubongo wa hifadhidata. Inatoa **huduma kadhaa za XPC** kama `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, na zaidi. Lakini pia **inahitaji entitlements kadhaa** kwa applications ili ziweze kutumia uwezo wa XPC ulio wazi, kama `.launchservices.changedefaulthandler` au `.launchservices.changeurlschemehandler` kubadilisha default apps kwa MIME types au URL schemes na mengine.

**`/System/Library/CoreServices/launchservicesd`** hudai service `com.apple.coreservices.launchservicesd` na inaweza kuulizwa kupata taarifa kuhusu applications zinazoendesha. Inaweza kuulizwa kwa kutumia system tool **`/usr/bin/lsappinfo`** au kwa [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Kwa mtazamo wa operator, kumbuka kuwa kwa kawaida kuna **views mbili muhimu**:

- **registration database** inayosimamiwa na LaunchServices / `lsd` (inayotegemea faili za `.csstore`).
- **per-user effective defaults** zilizohifadhiwa katika `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` ndani ya array `LSHandlers`.

Tofauti hii ni muhimu: application inaweza kuwa **imesajiliwa** kama inayoweza kushughulikia type au scheme, lakini **default ya sasa** bado inaweza kuwa bundle ID nyingine.

## File Extension & URL scheme app handlers

Mstari ufuatao unaweza kuwa muhimu kupata applications zinazoweza kufungua faili kulingana na extension:
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
## Kuorodhesha handlers zinazotumika

Faili yenye manufaa zaidi kwa **defaults za mtumiaji wa sasa** kwa kawaida ni:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Ili kutoa **URL scheme** handlers kutoka kwayo:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Ili ku-dump **content-type / UTI** handlers:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Ili kutatua mti wa UTI wa faili ya sampuli:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Ikiwa unataka CLI iliyo rafiki zaidi ya kuquery au kubadilisha defaults:
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
## Vifunguo vya Kuvutia vya Info.plist

Unapochambua application bundle, vifunguo hivi ndivyo muhimu zaidi:

- **`CFBundleDocumentTypes`**: makundi ya hati ambayo bundle inadai inaweza kufungua.
- **`LSItemContentTypes`**: njia ya **kisasa / inayopendekezwa** ya kuunganisha aina za hati na UTIs.
- **`LSHandlerRank`**: uainishaji unaotumiwa na LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes zilizotekelezwa na app.
- **`UTExportedTypeDeclarations`**: UTIs ambazo app **inamiliki**.
- **`UTImportedTypeDeclarations`**: UTIs ambazo app haimiliki lakini inataka system izitambue.

Amri ya haraka ya triage yenye manufaa ni:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Rasmi ndogo lakini muhimu: ikiwa **`LSItemContentTypes`** ipo, funguo za zamani kama **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, na **`CFBundleTypeOSTypes`** kwa kweli ni data ya uoanifu wa kihistoria. Kwa uamuzi halisi wa handler, zingatia kwanza njia ya UTI.

## Maelezo ya offensive

Applications hazihitaji kuendeshwa ili kuwa za kuvutia. Bundles ya `.app` iliyodondoshwa au kunakiliwa inaweza kuchambuliwa kiotomatiki na `lsd` mara tu inapoandikwa kwenye disk, na document types / URL schemes zake zilizotangazwa zinaweza kusajiliwa bila mtumiaji hata kuanzisha bundle.

Hii ni muhimu kwa **persistence / hijacking research** na pia kwa **initial-access chains**:

- App hasidi inaweza kudai **rare extension** au **custom UTI** na kusubiri mhanga afungue faili la lure.
- App hasidi inaweza kusajili **custom URL scheme** inayoweza kufikiwa kutoka browser, Electron app, office document, chat client, au helper app nyingine.
- Ukihariri app bundle baada ya kuibuild, unaweza kulazimisha LaunchServices kuiparse tena kwa:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Unapojaribu bundles za kushukiwa, zingatia hasa:

- **`LSHandlerRank=Owner`** kwenye aina zisizo za kawaida.
- **Mifumo pana ya `CFBundleDocumentTypes`** inayodai viendelezi vingi.
- **Helper / wrapper apps** ambazo tabia yao pekee ya kuvutia iko nyuma ya document au URI handler.
- **Faili zinazofanana na Shortcut** (`.webloc`, `.inetloc`, `.fileloc`) ambazo huishia ku-dispatch kwenda LaunchServices. Kwa hila za `.fileloc`-style na pembe zinazohusiana za Gatekeeper, angalia [ukurasa huu mwingine](macos-security-protections/macos-fs-tricks/README.md).

Ikiwa lengo lako ni passive code-execution kwa kutembelea tu folda au kuchagua faili, pia angalia ukurasa uliotengwa kwa [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), kwa kuwa hiyo ni surface tofauti lakini inayohusiana kwa karibu ya file-handler.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
