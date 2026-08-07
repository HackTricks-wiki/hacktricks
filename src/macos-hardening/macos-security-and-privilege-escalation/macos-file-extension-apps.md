# macOS-lêeruitbreiding- en URL scheme-app-hanteerders

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-databasis

Dit is ’n databasis van al die geïnstalleerde toepassings in macOS wat navraag gedoen kan word om inligting oor elke geïnstalleerde toepassing te verkry, soos ondersteunde **URL schemes**, **document types**, **UTIs** en verstek-hanteerders.

Dit is moontlik om hierdie databasis te dump met:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Of deur die tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) te gebruik.

**`/usr/libexec/lsd`** is die brein van die database. Dit verskaf **verskeie XPC services** soos `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, en meer. Dit **vereis egter ook sekere entitlements** vir applications om die blootgestelde XPC-funksionaliteit te kan gebruik, soos `.launchservices.changedefaulthandler` of `.launchservices.changeurlschemehandler` om default applications vir MIME types of URL schemes te verander, asook ander.

**`/System/Library/CoreServices/launchservicesd`** eis die service `com.apple.coreservices.launchservicesd` en kan navraag gedoen word om inligting oor running applications te verkry. Dit kan met die system tool **`/usr/bin/lsappinfo`** of met [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) bevraagteken word.

Vanuit ’n operator-perspektief, hou in gedagte dat daar gewoonlik **twee nuttige aansigte** is:

- Die **registration database** wat deur LaunchServices / `lsd` bestuur word (ondersteun deur `.csstore`-files).
- Die **per-user effective defaults** wat in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` binne die `LSHandlers` array gestoor word.

Hierdie onderskeid is belangrik: ’n application kan **geregistreer** wees as een wat ’n type of scheme kan hanteer, maar die **current default** kan steeds ’n ander bundle ID wees.

## File Extension & URL scheme app handlers

Die volgende lyn kan nuttig wees om die applications te vind wat files volgens die extension kan oopmaak:
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
Jy kan ook die uitbreidings wat deur ’n toepassing ondersteun word, nagaan deur:
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
## Enumerasie van effektiewe handlers

Die nuttigste lêer vir die **huidige gebruiker se verstekwaardes** is gewoonlik:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Om **URL scheme**-hanteerders daaruit te dump:
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
Om die UTI-boom van ’n voorbeeldlêer te bepaal:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
As jy ’n meer gebruikersvriendelike CLI wil hê om verstekwaardes te bevraagteken of te verander:
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

Wanneer ’n application bundle getriage word, is hierdie sleutels die belangrikste:

- **`CFBundleDocumentTypes`**: dokumentgroepe wat die bundle beweer dit kan oopmaak.
- **`LSItemContentTypes`**: die **moderne / voorkeur**-manier om dokumenttipes aan UTIs te bind.
- **`LSHandlerRank`**: rangorde wat deur LaunchServices gebruik word (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI-skemas wat deur die app geïmplementeer word.
- **`UTExportedTypeDeclarations`**: UTIs wat die app **besit**.
- **`UTImportedTypeDeclarations`**: UTIs wat die app nie besit nie, maar wat dit wil hê die stelsel moet herken.

’n Nuttige vinnige triage-opdrag is:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
’n Subtiele maar belangrike detail: indien **`LSItemContentTypes`** teenwoordig is, is ouer sleutels soos **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** en **`CFBundleTypeOSTypes`** effektief legacy-versoenbaarheidsdata. Vir werklike handler resolution, fokus eers op die UTI-pad.

## Offensiewe notas

Toepassings hoef nie uitgevoer te word om interessant te raak nie. ’n Neergelate of gekloonde `.app` bundle kan **outomaties deur `lsd` ontleed word sodra dit na die skyf geskryf is**, en sy verklaarde dokumenttipes / URL-skemas kan geregistreer word sonder dat die gebruiker ooit die bundle begin.

Dit is nuttig vir beide **persistence / hijacking-navorsing** en **initial-access-kettings**:

- ’n Kwaadwillige toepassing kan aanspraak maak op ’n **skaars uitbreiding** of ’n **custom UTI** en wag dat die slagoffer die lokval-lêer oopmaak.
- ’n Kwaadwillige toepassing kan ’n **custom URL-scheme** registreer wat vanaf ’n blaaier, Electron-toepassing, kantoordokument, chat-kliënt of ’n ander helper-toepassing bereik kan word.<sup>[[1]](#references)</sup>
- Indien jy ’n app bundle wysig nadat jy dit gebou het, kan jy LaunchServices dwing om dit weer te ontleed met:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Wanneer verdagte bundles getoets word, let veral op:

- **`LSHandlerRank=Owner`** op ongewone tipes.
- **Breë `CFBundleDocumentTypes`**-skikkings wat aanspraak maak op baie uitbreidings.
- **Helper- / wrapper-apps** waarvan die enigste interessante gedrag agter ’n document- of URI-handler versteek is.
- **Kortpadagtige lêers** (`.webloc`, `.inetloc`, `.fileloc`) wat uiteindelik na LaunchServices dispatch. Vir `.fileloc`-styl truuks en verwante Gatekeeper-hoeke, kyk na [hierdie ander bladsy](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

As jou doel passiewe code-execution is deur bloot na ’n folder te blaai of ’n lêer te kies, kyk ook na die toegewyde bladsy oor [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), aangesien dit ’n ander, maar nou verwante, file-handler-oppervlak is.

## Verwysings


- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
