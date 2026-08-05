# macOS Lêeruitbreiding- en URL scheme-app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-databasis

Dit is ’n databasis van al die geïnstalleerde applications in macOS wat navraagbaar is om inligting oor elke geïnstalleerde application te verkry, soos ondersteunde **URL schemes**, **dokumenttipes**, **UTIs** en verstek-handlers.

Dit is moontlik om hierdie databasis te dump met:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Of deur die instrument [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) te gebruik.

**`/usr/libexec/lsd`** is die brein van die databasis. Dit verskaf **verskeie XPC-dienste** soos `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, en meer. Maar dit **vereis ook sekere entitlements** vir toepassings om die blootgestelde XPC-funksionaliteit te kan gebruik, soos `.launchservices.changedefaulthandler` of `.launchservices.changeurlschemehandler` om verstektoepassings vir MIME-tipes of URL-skemas te verander, en ander.

**`/System/Library/CoreServices/launchservicesd`** eis die diens `com.apple.coreservices.launchservicesd` en kan navraag gedoen word om inligting oor lopende toepassings te verkry. Daar kan navraag gedoen word met die stelselinstrument **`/usr/bin/lsappinfo`** of met [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Vanuit ’n operateur se perspektief, hou in gedagte dat daar gewoonlik **twee nuttige aansigte** is:

- Die **registrasiedatabasis** wat deur LaunchServices / `lsd` bestuur word (ondersteun deur `.csstore`-lêers).
- Die **effektiewe verstekwaardes per gebruiker** wat in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` binne die `LSHandlers`-skikking gestoor word.

Hierdie onderskeid is belangrik: ’n toepassing kan **geregistreer** wees as in staat om ’n tipe of skema te hanteer, maar die **huidige verstek** kan steeds ’n ander bundle ID wees.

## Lêeruitbreiding- en URL-skema-app-hanteerders

Die volgende reël kan nuttig wees om die toepassings te vind wat lêers volgens hul uitbreiding kan oopmaak:
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
Jy kan ook die lêeruitbreidings wat deur ’n toepassing ondersteun word, nagaan deur:
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
## Enumerasie van effektiewe hanteerders

Die nuttigste lêer vir die **huidige gebruiker se verstekke** is gewoonlik:
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
Om die UTI-boom van ’n voorbeeldlêer te bepaal:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
As jy ’n meer gebruikersvriendelike CLI wil hê om verstekwaardes te raadpleeg of te verander:
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

Wanneer jy 'n application bundle triage, is hierdie sleutels die belangrikste:

- **`CFBundleDocumentTypes`**: dokumentgroepe wat die bundle beweer dit kan oopmaak.
- **`LSItemContentTypes`**: die **moderne / voorkeur**-metode om dokumenttipes aan UTIs te bind.
- **`LSHandlerRank`**: rangorde wat deur LaunchServices gebruik word (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: pasgemaakte URI-skemas wat deur die app geïmplementeer word.
- **`UTExportedTypeDeclarations`**: UTIs wat die app **besit**.
- **`UTImportedTypeDeclarations`**: UTIs wat die app nie besit nie, maar wat dit wil hê die stelsel moet herken.

'n Nuttige vinnige triage-opdrag is:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
'n Subtiele maar belangrike detail: indien **`LSItemContentTypes`** teenwoordig is, is ouer sleutels soos **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** en **`CFBundleTypeOSTypes`** effektief legacy-versoenbaarheidsdata. Vir werklike handler resolution, fokus eers op die UTI-pad.

## Offensive notes

Applications hoef nie uitgevoer te word om interessant te raak nie. 'n Gedropte of gekloonde `.app`-bundle kan **outomaties deur `lsd` geparse word sodra dit na die skyf geskryf is**, en die gedeclareerde dokumenttipes / URL-skemas daarvan kan geregistreer word sonder dat die gebruiker ooit die bundle launch.

Dit is nuttig vir beide **persistence / hijacking-navorsing** en **initial-access chains**:

- 'n Malicious app kan aanspraak maak op 'n **rare extension** of 'n **custom UTI** en wag dat die slagoffer die lure-lêer oopmaak.
- 'n Malicious app kan 'n **custom URL scheme** registreer wat bereikbaar is vanaf 'n browser, Electron-app, office-dokument, chat client of 'n ander helper-app.<sup>[[1]](#references)</sup>
- Indien jy 'n app-bundle ná die bou daarvan wysig, kan jy LaunchServices dwing om dit weer te parse met:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Wanneer verdagte bundles getoets word, let veral op:

- **`LSHandlerRank=Owner`** op ongewone tipes.
- **Breë `CFBundleDocumentTypes`**-skikkings wat aanspraak maak op baie extensies.
- **Helper- / wrapper-apps** waarvan die enigste interessante gedrag agter ’n document- of URI-handler versteek is.
- **Shortcut-agtige lêers** (`.webloc`, `.inetloc`, `.fileloc`) wat uiteindelik na LaunchServices dispatch. Vir `.fileloc`-styl tricks en verwante Gatekeeper-hoeke, kyk na [hierdie ander bladsy](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

As jou doel passive code-execution is deur bloot na ’n vouer te browse of ’n lêer te kies, kyk ook na die toegewyde bladsy oor [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), aangesien dit ’n ander maar nou verwante file-handler-oppervlak is.

## Verwysings

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
