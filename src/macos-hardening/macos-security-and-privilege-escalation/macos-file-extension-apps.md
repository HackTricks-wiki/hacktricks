# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-databasis

Dit is 'n databasis van al die geïnstalleerde toepassings in macOS wat bevraag kan word om inligting oor elke geïnstalleerde toepassing te verkry, soos ondersteunde **URL schemes**, **document types**, **UTIs** en verstekhandlers.

Dit is moontlik om hierdie databasis te dump met:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Of deur die tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) te gebruik.

**`/usr/libexec/lsd`** is die brein van die databasis. Dit verskaf **verskeie XPC services** soos `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, en meer. Maar dit **vereis ook sekere entitlements** vir applications om die blootgestelde XPC-functionaliteit te kan gebruik, soos `.launchservices.changedefaulthandler` of `.launchservices.changeurlschemehandler` om default applications vir MIME-tipes of URL-skemas te verander, en ander.

**`/System/Library/CoreServices/launchservicesd`** maak aanspraak op die service `com.apple.coreservices.launchservicesd` en kan bevraagteken word om inligting oor lopende applications te verkry. Dit kan bevraagteken word met die stelseltool **`/usr/bin/lsappinfo`** of met [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Vanuit ’n operator-perspektief, hou in gedagte dat daar gewoonlik **twee nuttige aansigte** is:

- Die **registration database** wat deur LaunchServices / `lsd` bestuur word (ondersteun deur `.csstore`-lêers).
- Die **per-user effective defaults** wat in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` binne die `LSHandlers`-array gestoor word.

Hierdie onderskeid is belangrik: ’n application kan **geregistreer** wees as in staat om ’n tipe of skema te hanteer, maar die **current default** kan steeds ’n ander bundle ID wees.

## File Extension & URL scheme app handlers

Die volgende reël kan nuttig wees om die applications te vind wat lêers volgens die extension kan oopmaak:
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
As jy 'n meer gebruikersvriendelike CLI wil hê om verstekwaardes te bevraagteken of te verander:
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

Wanneer 'n application bundle getriageer word, is hierdie sleutels die belangrikste:

- **`CFBundleDocumentTypes`**: dokumentgroepe wat die bundle beweer dit kan oopmaak.
- **`LSItemContentTypes`**: die **moderne / voorkeur**-manier om dokumenttipes aan UTIs te bind.
- **`LSHandlerRank`**: rangorde wat deur LaunchServices gebruik word (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI-skemas wat deur die app geïmplementeer word.
- **`UTExportedTypeDeclarations`**: UTIs wat die app **besit**.
- **`UTImportedTypeDeclarations`**: UTIs wat die app nie besit nie, maar wat dit deur die system herken wil laat word.

'n Nuttige vinnige triage command is:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
'n Subtiele maar belangrike detail: indien **`LSItemContentTypes`** teenwoordig is, is ouer sleutels soos **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** en **`CFBundleTypeOSTypes`** effektief legacy-versoenbaarheidsdata. Vir werklike handler-resolusie, fokus eerste op die UTI-pad.

## Offensive notes

Toepassings hoef nie uitgevoer te word om interessant te raak nie. 'n Geplaasde of gekloonde `.app`-bundle kan **outomaties deur `lsd` ontleed word sodra dit na die skyf geskryf is**, en die verklaarde dokumenttipes / URL-skemas kan geregistreer word sonder dat die gebruiker ooit die bundle begin.

Dit is nuttig vir beide **persistence / hijacking-navorsing** en **initial-access chains**:

- 'n Malicious app kan aanspraak maak op 'n **seldsame uitbreiding** of 'n **custom UTI** en wag totdat die slagoffer die lokval-lêer oopmaak.
- 'n Malicious app kan 'n **custom URL scheme** registreer wat bereikbaar is vanaf 'n browser, Electron-app, office-dokument, chat client of 'n ander helper-app.<sup>[1]</sup>
- Indien jy 'n app-bundle wysig nadat jy dit gebou het, kan jy LaunchServices dwing om dit weer te ontleed met:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Wanneer verdagte bundles getoets word, let veral op:

- **`LSHandlerRank=Owner`** op ongewone tipes.
- Breë **`CFBundleDocumentTypes`**-skikkings wat aanspraak maak op baie uitbreidings.
- **Helper / wrapper apps** waarvan die enigste interessante gedrag agter ’n document- of URI-handler versteek is.
- **Kortpad-agtige lêers** (`.webloc`, `.inetloc`, `.fileloc`) wat uiteindelik na LaunchServices dispatch. Vir `.fileloc`-styl-truuks en verwante Gatekeeper-hoeke, kyk na [hierdie ander bladsy](macos-security-protections/macos-fs-tricks/README.md).<sup>[2]</sup>

As jou doel passiewe code-execution is deur bloot na ’n vouer te blaai of ’n lêer te kies, kyk ook na die toegewyde bladsy vir [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), aangesien dit ’n ander, maar nouverwante file-handler-oppervlak is.

## Verwysings

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
