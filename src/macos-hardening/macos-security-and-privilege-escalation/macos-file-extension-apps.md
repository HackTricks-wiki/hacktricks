# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Dit is 'n databasis van al die geïnstalleerde toepassings in macOS wat bevraagteken kan word om inligting te kry oor elke geïnstalleerde toepassing soos ondersteunde **URL schemes**, **document types**, **UTIs**, en verstek handlers.

Dit is moontlik om hierdie databasis te dump met:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Of using the tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** is die brein van die databasis. Dit verskaf **verskeie XPC services** soos `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, en meer. Maar dit **vereis ook sekere entitlements** vir applications om die blootgestelde XPC functionalities te kan gebruik, soos `.launchservices.changedefaulthandler` of `.launchservices.changeurlschemehandler` om default apps vir MIME types of URL schemes te verander en ander.

**`/System/Library/CoreServices/launchservicesd`** eis die service `com.apple.coreservices.launchservicesd` op en kan bevraagteken word om inligting oor lopende applications te kry. Dit kan bevraagteken word met die system tool **`/usr/bin/lsappinfo`** of met [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Van 'n operator-perspektief, hou in gedagte daar is gewoonlik **two useful views**:

- Die **registration database** bestuur deur LaunchServices / `lsd` (gerugsteun deur `.csstore` files).
- Die **per-user effective defaults** gestoor in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` binne die `LSHandlers` array.

Hierdie onderskeid maak saak: 'n application kan **registered** wees as in staat om 'n type of scheme te hanteer, maar die **current default** kan steeds 'n ander bundle ID wees.

## File Extension & URL scheme app handlers

Die volgende reël kan nuttig wees om die applications te vind wat files kan oopmaak afhangende van die extension:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Of gebruik iets soos [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Jy kan ook die uitbreidings wat deur 'n toepassing ondersteun word, nagaan deur:
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
## Lys effektiewe handlers

Die nuttigste lêer vir die **huidige gebruiker se verstekwaardes** is gewoonlik:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Om **URL scheme**-handlers daaruit te dump:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Om **content-type / UTI** handlers te dump:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Om die UTI-boom van ’n voorbeeldlêer op te los:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
As jy ’n meer vriendelike CLI wil hê om defaults te query of te verander:
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
## Interessante Info.plist-sleutels

Wanneer jy ’n toepassingbundel triageer, maak hierdie sleutels die meeste saak:

- **`CFBundleDocumentTypes`**: dokumentgroepe wat die bundel beweer dit kan oopmaak.
- **`LSItemContentTypes`**: die **moderne / voorkeur** manier om dokumenttipes aan UTIs te bind.
- **`LSHandlerRank`**: rangorde wat deur LaunchServices gebruik word (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: pasgemaakte URI-skemas wat deur die app geïmplementeer word.
- **`UTExportedTypeDeclarations`**: UTIs wat die app **besit**.
- **`UTImportedTypeDeclarations`**: UTIs wat die app nie besit nie maar wil hê die stelsel moet herken.

’n Nuttige vinnige triage-opdrag is:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
’n Subtiele maar belangrike detail: as **`LSItemContentTypes`** teenwoordig is, is ouer sleutels soos **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, en **`CFBundleTypeOSTypes`** in die praktyk legacy versoeningsdata. Vir werklike handler-resolusie, fokus eers op die UTI-pad.

## Offensive notes

Applications hoef nie uitgevoer te word om interessant te word nie. ’n Gedropte of gekloonde `.app` bundle kan **outomaties deur `lsd` gepars word sodra dit na skyf geskryf word**, en sy verklaarde document types / URL schemes kan geregistreer word sonder dat die user ooit die bundle launch.

Dit is nuttig vir beide **persistence / hijacking research** en **initial-access chains**:

- ’n Kwaadwillige app kan ’n **rare extension** of ’n **custom UTI** eis en wag vir die victim om die loklêer oop te maak.
- ’n Kwaadwillige app kan ’n **custom URL scheme** registreer wat bereikbaar is vanaf ’n browser, Electron app, office document, chat client, of ’n ander helper app.
- As jy ’n app bundle ná bou wysig, kan jy LaunchServices dwing om dit weer te parse met:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Wanneer jy verdagte bundles toets, let veral op:

- **`LSHandlerRank=Owner`** op ongewone tipes.
- **Breë `CFBundleDocumentTypes`**-arrays wat baie uitbreidings eis.
- **Helper / wrapper apps** wie se enigste interessante gedrag agter ’n document- of URI-handler is.
- **Shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`) wat uiteindelik in LaunchServices uitkom. Vir `.fileloc`-styl truuks en verwante Gatekeeper-hoeke, kyk [hierdie ander bladsy](macos-security-protections/macos-fs-tricks/README.md).

As jou doel passiewe code-execution is van bloot na ’n folder blaai of ’n file kies, kyk ook na die toegewyde bladsy vir [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), aangesien dit ’n ander maar nou verwante file-handler-oppervlak is.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
