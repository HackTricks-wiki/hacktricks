# macOS-lêeruitbreiding- en URL-skematoepassingshanteerders

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-databasis

Dit is ’n databasis van al die geïnstalleerde toepassings in macOS. Jy kan dit navraag doen om inligting oor elke geïnstalleerde toepassing te kry, soos ondersteunde **URL-skemas**, **dokumenttipes**, **UTI's** en verstekhanteerders.

Dit is moontlik om hierdie databasis met die volgende opdrag te dump:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Of gebruik die tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** is die brein van die databasis. Dit verskaf **verskeie XPC-dienste** soos `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, en meer. Maar dit **vereis ook sekere entitlements** vir toepassings om die blootgestelde XPC-funksionaliteit te kan gebruik, soos `.launchservices.changedefaulthandler` of `.launchservices.changeurlschemehandler` om verstektoepassings vir MIME-tipes of URL-skemas te verander, en ander.

**`/System/Library/CoreServices/launchservicesd`** registreer die diens `com.apple.coreservices.launchservicesd` en kan navraag daaroor gedoen word om inligting oor toepassings wat tans loop, te kry. Jy kan dit navraag doen met die stelselhulpmiddel **`/usr/bin/lsappinfo`** of met [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Hou vanuit ’n operateur se perspektief in gedagte dat daar gewoonlik **twee nuttige aansigte** is:

- Die **registrasiedatabasis** wat deur LaunchServices / `lsd` bestuur word (gerugsteun deur `.csstore`-lêers).
- Die **effektiewe verstekwaardes per gebruiker** wat in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` binne die `LSHandlers`-skikking gestoor word.

Hierdie onderskeid is belangrik: ’n toepassing kan **geregistreer** wees as geskik om ’n tipe of skema te hanteer, maar die **huidige verstektoepassing** kan steeds ’n ander bundle ID wees.

Op onlangse macOS-weergawes is registrasie-ontdekking nie beperk tot `/Applications` nie: toepassings in ander Spotlight-sigbare, toeganklike vouers en gemonteerde/gedeelde volumes kan in die register beland. Behou dus die `path`- en volume-inligting van `lsregister -dump` tydens triage, en moenie aanvaar dat die deregistrasie van ’n toepassing permanent is terwyl die bundle steeds ontdekbaar is nie.<sup>[[4]](#references)</sup>

## Lêeruitbreiding- en URL-skema-toepassingshanteerders

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

## Effektiewe handlers opnoem

Die nuttigste lêer vir die **huidige gebruiker se verstekinstellings** is gewoonlik:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Om **URL scheme**-hanteerders daaruit te dump:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Om **content-type / UTI**-handlers te dump:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Om die UTI-boom vir ’n voorbeeldlêer te bepaal:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

As jy ’n gebruikersvriendeliker CLI wil hê om verstekwaardes te raadpleeg of te verander:

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

Die hanteerderbepaling het ook ’n **lêerspesifieke** laag. Voordat LaunchServices terugval op die lêer se UTI en die gebruiker se globale verstek, kontroleer dit die uitgebreide kenmerk `com.apple.LaunchServices.OpenWith`. Finder skep dit wanneer **Maak altyd oop met** vir een lêer gekies word; die waarde daarvan is ’n binêre eiendomslys wat ’n toepassingspad, bondelidentifiseerder en weergaweselektor bevat.<sup>[[3]](#references)</sup>

Inspekteer en dekodeer dit sonder om die lêernaamuitbreiding te vertrou:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Dit is nuttig wanneer ’n enkele lure in ’n onverwagte toepassing oopmaak, al rapporteer `duti`, `dutix` of `LSHandlers` ’n onskadelike globale verstek. In ’n beheerde lab kan die presiese ondeursigtige waarde gekopieer word vanaf ’n lêer wat deur Finder gekonfigureer is; as jy dit uitvee, word normale tipegebaseerde resolusie herstel:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Interessante Info.plist-sleutels

Wanneer jy ’n application bundle triage, is hierdie sleutels die belangrikste:

- **`CFBundleDocumentTypes`**: dokumentgroepe wat die bundle beweer dit kan oopmaak.
- **`LSItemContentTypes`**: die **moderne / voorkeur**-manier om dokumenttipes aan UTIs te koppel.
- **`LSHandlerRank`**: rangorde wat deur LaunchServices gebruik word (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: pasgemaakte URI-skemas wat deur die app geïmplementeer word.
- **`UTExportedTypeDeclarations`**: UTIs wat die app **besit**.
- **`UTImportedTypeDeclarations`**: UTIs wat die app nie besit nie, maar wil hê die stelsel moet herken.

’n Nuttige vinnige triage-opdrag is:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

’n Subtiele maar belangrike besonderheid: as **`LSItemContentTypes`** teenwoordig is, is ouer sleutels soos **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** en **`CFBundleTypeOSTypes`** in wese legacy-versoenbaarheidsdata. Vir werklike handler-resolusie, fokus eers op die UTI-pad.

## Aanvallende notas

Toepassings hoef nie uitgevoer te word om interessant te raak nie. ’n Neergesette of gekloonde `.app`-bundle kan **outomaties deur `lsd` ontleed word sodra dit na die skyf geskryf word**, en die dokumenttipes / URL-skemas wat daarin verklaar word, kan geregistreer word sonder dat die gebruiker ooit die bundle begin.

Dit is nuttig vir beide **persistence / hijacking-navorsing** en **initial-access-kettings**:

- ’n Kwaadwillige toepassing kan aanspraak maak op ’n **seldsame uitbreiding** of ’n **pasgemaakte UTI** en wag dat die slagoffer die loklêer oopmaak.
- ’n Kwaadwillige toepassing kan ’n **pasgemaakte URL-skema** registreer wat bereikbaar is vanaf ’n browser, Electron-toepassing, Office-dokument, chat-kliënt of ’n ander helper-toepassing.<sup>[[1]](#references)</sup>
- Om normale verstekresolusie te onderskei van toetsing van ’n spesifieke kandidaat-handler, roep die skema deur LaunchServices aan met `open 'targetscheme://host/path?value=test'`, en rig dit dan op ’n spesifieke geregistreerde bundle met `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Dit is nuttig om te oudit hoe die ontvangende toepassing aanvaller-beheerde URL-komponente valideer en dekodeer.<sup>[[1]](#references)</sup>
- As jy ’n app-bundle wysig nadat jy dit gebou het, kan jy LaunchServices dwing om dit weer te ontleed met:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Wanneer jy verdagte bundles toets, let veral op:

- **`LSHandlerRank=Owner`** vir ongewone tipes.
- **Breë `CFBundleDocumentTypes`**-skikkings wat baie uitbreidings opeis.
- **Helper- / wrapper-apps** waarvan die enigste interessante gedrag agter ’n dokument- of URI-handler skuil.
- **Kortpadagtige lêers** (`.webloc`, `.inetloc`, `.fileloc`) wat uiteindelik na LaunchServices stuur. Vir `.fileloc`-agtige truuks en verwante Gatekeeper-aspekte, kyk na [hierdie ander bladsy](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

As jou doel passiewe code-execution is deur bloot na ’n vouer te blaai of ’n lêer te kies, kyk ook na die toegewyde bladsy oor [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), aangesien dit ’n ander maar nou verwante lêerhandler-aanvalsoppervlak is.



## References

- [1] [Objective-See - Afstanduitbuiting van Mac via pasgemaakte URL-skemas](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Om die hek te omseil: ’n nader kyk na Gatekeeper-foute op macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Hoe macOS ’n lêer in die korrekte app oopmaak](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Beheer van LaunchServices in macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
