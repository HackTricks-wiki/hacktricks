# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Hii ni database ya application zote zilizosakinishwa katika macOS ambayo inaweza ku-queried ili kupata taarifa kuhusu kila application iliyosakinishwa, kama vile **URL schemes**, **document types**, **UTIs**, na default handlers.

Inawezekana ku-dump database hii kwa:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Au kwa kutumia tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ndiyo kiini cha database. Inatoa **huduma kadhaa za XPC** kama vile `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, na nyinginezo. Lakini pia **inahitaji entitlements fulani** kwa applications ili ziweze kutumia functionalities za XPC zilizowekwa wazi, kama vile `.launchservices.changedefaulthandler` au `.launchservices.changeurlschemehandler` za kubadilisha apps za default kwa MIME types au URL schemes, pamoja na nyinginezo.

**`/System/Library/CoreServices/launchservicesd`** inadai service `com.apple.coreservices.launchservicesd` na inaweza kuulizwa ili kupata taarifa kuhusu applications zinazoendeshwa. Inaweza kuulizwa kwa kutumia system tool **`/usr/bin/lsappinfo`** au kwa kutumia [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Kwa mtazamo wa operator, kumbuka kwamba kwa kawaida kuna **mionekano miwili muhimu**:

- **Registration database** inayodhibitiwa na LaunchServices / `lsd` (inayotegemezwa na files za `.csstore`).
- **Per-user effective defaults** zilizohifadhiwa katika `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` ndani ya array ya `LSHandlers`.

Tofauti hii ni muhimu: application inaweza kuwa **imesajiliwa** kuwa inaweza kushughulikia type au scheme fulani, lakini **default ya sasa** bado inaweza kuwa bundle ID nyingine.

Kwenye matoleo ya hivi karibuni ya macOS, ugunduzi wa registrations hauishii kwenye `/Applications`: apps zilizo katika folders nyingine zinazoonekana na Spotlight na zinazoweza kufikiwa, pamoja na mounted/shared volumes, zinaweza kuingia kwenye registry. Kwa hivyo, hifadhi taarifa za `path` na volume kutoka `lsregister -dump` wakati wa triage na usidhani kwamba unregistering app kutadumu wakati bundle bado inaweza kugunduliwa.<sup>[[4]](#references)</sup>

## Vishughulikiaji vya apps vya File Extension na URL scheme

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
Unaweza pia kuangalia extensions zinazotumika na application kwa kufanya:
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
Ili kufanya dump ya handlers za **URL scheme** kutoka humo:
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
Ikiwa unataka CLI iliyo rafiki zaidi ya kuuliza au kubadilisha defaults:
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
### Ubadilishaji wa `Open With` kwa kila faili

Utatuzi wa handler pia una safu **maalum kwa faili**. Kabla ya kurejea kwenye UTI ya faili na chaguo-msingi la jumla la mtumiaji, LaunchServices hukagua extended attribute ya `com.apple.LaunchServices.OpenWith`. Finder huiunda wakati **Always Open With** inapochaguliwa kwa faili moja; thamani yake ni binary property list iliyo na njia ya application, kitambulishi cha bundle, na kiteuzi cha toleo.<sup>[[3]](#references)</sup>

Ikague na ui-decode bila kuamini file extension:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
Hii ni muhimu wakati lure moja inafunguka kwa application isiyotarajiwa ingawa `duti`, `dutix`, au `LSHandlers` inaonyesha default ya kimataifa isiyo na madhara. Kwa maabara inayodhibitiwa, value halisi ya opaque inaweza kunakiliwa kutoka kwenye file lililosanidiwa kupitia Finder; kuifuta hurejesha utatuzi wa kawaida kulingana na aina:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Vifunguo vya kuvutia vya Info.plist

Unapofanya triage ya application bundle, vifunguo hivi vina umuhimu mkubwa zaidi:

- **`CFBundleDocumentTypes`**: makundi ya document ambayo bundle inadai inaweza kufungua.
- **`LSItemContentTypes`**: njia **ya kisasa / inayopendelewa** ya kuhusisha document types na UTIs.
- **`LSHandlerRank`**: mpangilio wa nafasi unaotumiwa na LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes zinazotekelezwa na app.
- **`UTExportedTypeDeclarations`**: UTIs ambazo app **inamiliki**.
- **`UTImportedTypeDeclarations`**: UTIs ambazo app haimiliki lakini inataka mfumo uzitambue.

Amri muhimu ya haraka ya triage ni:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Maelezo madogo lakini muhimu: ikiwa **`LSItemContentTypes`** ipo, keys za zamani kama **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, na **`CFBundleTypeOSTypes`** kimsingi ni data za legacy compatibility. Kwa ajili ya utatuzi halisi wa handler, anza na njia ya UTI.

## Maelezo ya mashambulizi

Applications hazihitaji kutekelezwa ili ziwe muhimu. Bundle ya `.app` iliyodropped au iliyoclone inaweza **kuchanganuliwa kiotomatiki na `lsd` mara tu inapoandikwa kwenye disk**, na aina za document / URL schemes ilizotangaza zinaweza kusajiliwa bila mtumiaji kuanzisha bundle hiyo wakati wowote.

Hii ni muhimu kwa **utafiti wa persistence / hijacking** na pia kwa **initial-access chains**:

- App hasidi inaweza kudai **extension adimu** au **UTI maalum** na kusubiri victim afungue faili ya mtego.
- App hasidi inaweza kusajili **custom URL scheme** inayoweza kufikiwa kutoka kwa browser, Electron app, office document, chat client, au helper app nyingine.<sup>[[1]](#references)</sup>
- Ili kutenganisha utatuzi wa kawaida wa default na testing ya handler fulani, invoke scheme kupitia LaunchServices kwa `open 'targetscheme://host/path?value=test'`, kisha target bundle maalum iliyosajiliwa kwa `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Hii ni muhimu kwa auditing ya jinsi app inayopokea inavyovalidate na kudecode vipengele vya URL vinavyodhibitiwa na attacker.<sup>[[1]](#references)</sup>
- Ukiedit app bundle baada ya kuijenga, unaweza kulazimisha LaunchServices kuichanganua tena kwa:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Wakati wa kujaribu bundles zinazotia shaka, zingatia hasa:

- **`LSHandlerRank=Owner`** kwenye aina zisizo za kawaida.
- Arrays pana za **`CFBundleDocumentTypes`** zinazodai extensions nyingi.
- Apps za helper / wrapper ambazo tabia yake pekee ya kuvutia iko nyuma ya document au URI handler.
- Files zinazofanana na shortcuts (`.webloc`, `.inetloc`, `.fileloc`) ambazo huishia kupeleka utekelezaji kwenye LaunchServices. Kwa tricks za aina ya `.fileloc` na mitazamo inayohusiana na Gatekeeper, angalia [ukurasa huu mwingine](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Ikiwa lengo lako ni passive code-execution kwa kuvinjari tu folder au kuchagua file, pia angalia ukurasa maalum wa [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), kwa kuwa huo ni uso tofauti lakini unaohusiana kwa karibu wa file-handler.



## References

- [1] [Objective-See - Exploitation ya Mac za mbali kupitia Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Kupita Gate: Kuangalia kwa karibu dosari za Gatekeeper kwenye macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Jinsi macOS inavyofungua file katika app sahihi](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Kudhibiti LaunchServices katika macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
