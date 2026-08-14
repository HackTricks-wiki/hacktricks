# macOS-lêeruitbreiding- en URL-skematoepassingshanteerders

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-databasis

Dit is ’n databasis van al die geïnstalleerde toepassings in macOS wat navraaggedoen kan word om inligting oor elke geïnstalleerde toepassing te verkry, soos ondersteunde **URL-skemas**, **dokumenttipes**, **UTIs** en verstekhanteerders.

Dit is moontlik om hierdie databasis met die volgende af te laai:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Of gebruik die hulpmiddel [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** is die brein van die databasis. Dit verskaf **verskeie XPC-dienste** soos `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, en meer. Dit **vereis egter ook sekere entitlements** vir toepassings om die blootgestelde XPC-funksionaliteite te kan gebruik, soos `.launchservices.changedefaulthandler` of `.launchservices.changeurlschemehandler` om verstektoepassings vir MIME-tipes of URL-skemas te verander, en ander.

**`/System/Library/CoreServices/launchservicesd`** eis die diens `com.apple.coreservices.launchservicesd` en kan bevraagteken word om inligting oor lopende toepassings te verkry. Dit kan bevraagteken word met die stelselhulpmiddel **`/usr/bin/lsappinfo`** of met [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Vanuit ’n operateursperspektief, hou in gedagte dat daar gewoonlik **twee nuttige aansigte** is:

- Die **registrasiedatabasis** wat deur LaunchServices / `lsd` bestuur word (ondersteun deur `.csstore`-lêers).
- Die **effektiewe verstekwaardes per gebruiker** wat in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` binne die `LSHandlers`-skikking gestoor word.

Hierdie onderskeid is belangrik: ’n toepassing kan **geregistreer** wees as ’n toepassing wat ’n tipe of skema kan hanteer, maar die **huidige verstek** kan steeds ’n ander bundel-ID wees.

Op onlangse macOS-vrystellings is registrasie-ontdekking nie beperk tot `/Applications` nie: toepassings in ander Spotlight-sigbare, toeganklike vouers en gemonteerde/gedeelde volumes kan ook in die register opgeneem word. Bewaar dus die `path`- en volume-inligting uit `lsregister -dump` tydens triage, en moenie aanvaar dat die de-registrasie van ’n toepassing blywend is terwyl die bundel ontdekbaar bly nie.<sup>[[4]](#references)</sup>

## Toepassingshanteerders vir lêeruitbreidings en URL-skemas

Die volgende reël kan nuttig wees om die toepassings te vind wat lêers volgens die uitbreiding kan oopmaak:
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
## Effektiewe handlers opsom

Die nuttigste lêer vir die **huidige gebruiker se verstekke** is gewoonlik:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Om **URL scheme** handlers daaruit te dump:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Om **content-type / UTI**-hanteerders te dump:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Om die UTI-boom van ’n voorbeeldlêer op te los:
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
### Per-lêer `Open With`-oorheersings

Hanteerderresolusie het ook ’n **lêerspesifieke** laag. Voordat dit na die lêer se UTI en die gebruiker se globale verstek terugval, kontroleer LaunchServices die `com.apple.LaunchServices.OpenWith`-uitgebreide attribuut. Finder skep dit wanneer **Always Open With** vir een lêer gekies word; die waarde daarvan is ’n binêre property list wat ’n toepassingspad, bondelidentifiseerder en weergawe-selektor bevat.<sup>[[3]](#references)</sup>

Inspekteer en dekodeer dit sonder om die lêernaamuitbreiding te vertrou:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
Dit is nuttig wanneer ’n enkele lokmiddel met ’n onverwagte toepassing oopmaak, selfs al rapporteer `duti`, `dutix` of `LSHandlers` ’n onskadelike globale verstektoepassing. In ’n beheerde laboratorium kan die presiese ondeursigtige waarde gekopieer word vanaf ’n lêer wat deur Finder gekonfigureer is; as dit verwyder word, word normale tipegebaseerde resolusie herstel:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Interessante Info.plist-sleutels

Wanneer 'n application bundle getriageer word, is hierdie sleutels die belangrikste:

- **`CFBundleDocumentTypes`**: dokumentgroepe wat die bundle beweer dit kan oopmaak.
- **`LSItemContentTypes`**: die **moderne / voorkeur**-manier om dokumenttipes aan UTIs te bind.
- **`LSHandlerRank`**: rangorde wat deur LaunchServices gebruik word (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes wat deur die app geïmplementeer word.
- **`UTExportedTypeDeclarations`**: UTIs wat die app **besit**.
- **`UTImportedTypeDeclarations`**: UTIs wat die app nie besit nie, maar wat dit wil hê die stelsel moet herken.

'n Nuttige vinnige triage-opdrag is:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
’n Subtiele maar belangrike detail: indien **`LSItemContentTypes`** teenwoordig is, is ouer sleutels soos **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** en **`CFBundleTypeOSTypes`** effektief legacy-versoenbaarheidsdata. Vir werklike handler-resolusie, fokus eers op die UTI-pad.

## Offensiewe notas

Toepassings hoef nie uitgevoer te word om interessant te wees nie. ’n `.app`-bundle wat gedrop of gekloon is, kan **outomaties deur `lsd` geparse word sodra dit na die skyf geskryf word**, en die verklaarde dokumenttipes / URL-skemas daarvan kan geregistreer word sonder dat die gebruiker ooit die bundle begin.

Dit is nuttig vir sowel **persistence / hijacking-navorsing** as **initial-access-kettings**:

- ’n Kwaadwillige toepassing kan aanspraak maak op ’n **skaars uitbreiding** of ’n **custom UTI** en wag dat die slagoffer die lokval-lêer oopmaak.
- ’n Kwaadwillige toepassing kan ’n **custom URL scheme** registreer wat vanaf ’n blaaier, Electron-toepassing, kantoordokument, chat-kliënt of ’n ander helper-toepassing bereikbaar is.<sup>[[1]](#references)</sup>
- Om normale verstekresolusie te skei van die toets van ’n spesifieke kandidaat-handler, roep die skema deur LaunchServices aan met `open 'targetscheme://host/path?value=test'`, en teiken dan ’n spesifieke geregistreerde bundle met `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Dit is nuttig om te oudit hoe die ontvangende toepassing aanvaller-beheerde URL-komponente valideer en dekodeer.<sup>[[1]](#references)</sup>
- Indien jy ’n toepassing se bundle ná die bou daarvan wysig, kan jy LaunchServices dwing om dit weer te parse met:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Wanneer verdagte bundles getoets word, let veral op:

- **`LSHandlerRank=Owner`** op ongewone tipes.
- **Breë `CFBundleDocumentTypes`**-arrays wat baie extensies opeis.
- **Helper-/wrapper-apps** waarvan die enigste interessante gedrag agter ’n document- of URI-handler versteek is.
- **Shortcut-agtige lêers** (`.webloc`, `.inetloc`, `.fileloc`) wat uiteindelik na LaunchServices dispatch. Vir `.fileloc`-agtige tricks en verwante Gatekeeper-hoeke, kyk na [hierdie ander bladsy](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

As jou doel passiewe code-execution is deur bloot na ’n folder te browse of ’n lêer te kies, kyk ook na die toegewyde bladsy oor [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), aangesien dit ’n ander, maar nouverwante file-handler-oppervlak is.



## References

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Om die hek te omseil: ’n Nader kyk na Gatekeeper-foute op macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Hoe macOS ’n lêer in die korrekte app oopmaak](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Beheer van LaunchServices in macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
