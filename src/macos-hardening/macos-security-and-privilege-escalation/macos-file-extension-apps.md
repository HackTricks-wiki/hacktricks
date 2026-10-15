# macOS-lêeruitbreiding- en URL-skema-apphanteerders

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-databasis

Dit is ’n databasis van al die geïnstalleerde toepassings in macOS wat navraag gedoen kan word om inligting oor elke geïnstalleerde toepassing te kry, soos ondersteunde **URL-skemas**, **dokumenttipes**, **UTI’s** en verstekhanteerders.

Dit is moontlik om hierdie databasis te dump met:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Of gebruik die hulpmiddel [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** is die brein van die databasis. Dit bied **verskeie XPC-dienste**, soos `.lsd.installation`, `.lsd.open`, `.lsd.openurl` en meer. Maar dit **vereis ook sekere entitlements** van toepassings om die blootgestelde XPC-funksies te kan gebruik, soos `.launchservices.changedefaulthandler` of `.launchservices.changeurlschemehandler` om verstektoepassings vir MIME-tipes of URL-skemas te verander, en ander.

**`/System/Library/CoreServices/launchservicesd`** bied die diens `com.apple.coreservices.launchservicesd` aan en kan navraag daaroor gedoen word om inligting oor lopende toepassings te kry. Daaroor kan navraag gedoen word met die stelselhulpmiddel **`/usr/bin/lsappinfo`** of met [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Hou vanuit ’n operateurperspektief in gedagte dat daar gewoonlik **twee nuttige aansigte** is:

- Die **registrasiedatabasis** wat deur LaunchServices / `lsd` bestuur word (gerugsteun deur `.csstore`-lêers).
- Die **effektiewe verstekke per gebruiker** wat in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` binne die `LSHandlers`-skikking gestoor word.

Hierdie onderskeid is belangrik: ’n toepassing kan **geregistreer wees** as een wat ’n tipe of skema kan hanteer, maar die **huidige verstektoepassing** kan steeds ’n ander bundle ID wees.

In onlangse macOS-weergawes is die ontdekking van registrasies nie beperk tot `/Applications` nie: toepassings in ander Spotlight-sigbare, toeganklike vouers en gemonteerde/gedeelde volumes kan in die register opgeneem word. Bewaar dus die `path`- en volume-inligting van `lsregister -dump` tydens triage, en moenie aanvaar dat die deregistrasie van ’n toepassing permanent is terwyl die bundel steeds ontdekbaar is nie.<sup>[[4]](#references)</sup>

## Lêeruitbreiding- en URL-skema-toepassingshanteerders

Die volgende reël kan nuttig wees om die toepassings te vind wat lêers kan oopmaak, afhangend van die uitbreiding:

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

## Enumerering van effektiewe handlers

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

Om die UTI-boom van ’n voorbeeldlêer op te los:

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

### Per-lêer `Open With`-oorheersings

Handler-resolusie het ook ’n **lêerspesifieke** laag. Voordat LaunchServices terugval op die lêer se UTI en die gebruiker se globale verstek, kontroleer dit die `com.apple.LaunchServices.OpenWith`-uitgebreide attribuut. Finder skep dit wanneer **Always Open With** vir een lêer gekies word; die waarde daarvan is ’n binêre eiendomslys wat ’n toepassingpad, bondelidentifiseerder en weergaweselektor bevat.<sup>[[3]](#references)</sup>

Inspekteer en dekodeer dit sonder om die lêernaamuitbreiding te vertrou:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Dit is nuttig wanneer ’n enkele lokmiddel met ’n onverwagte toepassing oopmaak, hoewel `duti`, `dutix` of `LSHandlers` ’n onskadelike globale verstek rapporteer. In ’n beheerde laboratorium kan die presiese ondeursigtige waarde gekopieer word vanaf ’n lêer wat deur Finder opgestel is; deur dit te verwyder, word die normale tipegebaseerde resolusie herstel:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Interessante Info.plist-sleutels

Wanneer ’n toepassingsbundel getriageer word, is hierdie sleutels die belangrikste:

- **`CFBundleDocumentTypes`**: dokumentgroepe wat die bundel beweer dit kan oopmaak.
- **`LSItemContentTypes`**: die **moderne / voorkeur** manier om dokumenttipes aan UTIs te koppel.
- **`LSHandlerRank`**: rangskikking wat deur LaunchServices gebruik word (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: pasgemaakte URI-skemas wat deur die toepassing geïmplementeer word.
- **`UTExportedTypeDeclarations`**: UTIs wat die toepassing **besit**.
- **`UTImportedTypeDeclarations`**: UTIs wat die toepassing nie besit nie, maar wil hê die stelsel moet herken.

’n Nuttige vinnige triage-opdrag is:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

’n Subtiele maar belangrike besonderheid: as **`LSItemContentTypes`** teenwoordig is, is ouer sleutels soos **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** en **`CFBundleTypeOSTypes`** in effek verouderde versoenbaarheidsdata. Vir werklike handler-resolusie moet jy eers op die UTI-pad fokus.

## Offensiewe notas

Toepassings hoef nie te loop voordat hul handler-aansprake interessant word nie, maar **die skryf van ’n `.app`-bundel alleen waarborg nie onmiddellike registrasie nie**. Finder kan ’n toepassing registreer wanneer dit dit ontdek, onder meer wanneer ’n gebruiker deur die toepassing se vouer blaai; registrasie kan ook tydens selflaai of aanmelding plaasvind, of deur ’n eksplisiete registrasie-oproep. Gaan `lsregister -dump` na voordat jy ’n aanspraak toets. Registrasie alleen begin nie die toepassing nie en maak dit ook nie die effektiewe verstektoepassing nie.<sup>[[5]](#references)</sup> Sien [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices) vir die voorvereistes vir persistence.

Dit is nuttig vir sowel **persistence / hijacking-navorsing** as **aanvanklike-toegang-kettings**:

- ’n Kwaadwillige toepassing kan aanspraak maak op ’n **skaars lêeruitbreiding** of ’n **pasgemaakte UTI**, en wag totdat die slagoffer die loklêer oopmaak.
- ’n Kwaadwillige toepassing kan ’n **pasgemaakte URL-scheme** registreer wat bereikbaar is vanaf ’n blaaier, Electron-toepassing, kantoordokument, kletskliënt of ’n ander hulptoepassing.<sup>[[1]](#references)</sup>
- Om normale verstek-resolusie van die toetsing van ’n spesifieke kandidaat-handler te onderskei, roep die scheme deur LaunchServices aan met `open 'targetscheme://host/path?value=test'`, en teiken dan ’n spesifieke geregistreerde bundel met `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Dit is nuttig om te oudit hoe die ontvangende toepassing attacker-controlled URL-komponente valideer en dekodeer.<sup>[[1]](#references)</sup>
- As jy ’n toepassing se bundel wysig nadat jy dit gebou het, kan jy LaunchServices dwing om dit weer te ontleed met:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Wanneer verdagte bundels getoets word, let veral op:

- **`LSHandlerRank=Owner`** vir ongewone tipes.
- Breë **`CFBundleDocumentTypes`**-skikkings wat beweer dat hulle baie lêeruitbreidings hanteer.
- **Helper- / wrapper-apps** waarvan die enigste interessante gedrag agter ’n dokument- of URI-handler skuil.
- **Kortpadagtige lêers** (`.webloc`, `.inetloc`, `.fileloc`) wat uiteindelik na LaunchServices deurstuur. Kyk na [hierdie ander bladsy](macos-security-protections/macos-fs-tricks/README.md) vir truuks in die `.fileloc`-styl en verwante Gatekeeper-aspekte.<sup>[[2]](#references)</sup>

### URL-parameters wat na stroomaf-opsies deurgegee word

’n Blaaier se bevestiging vir ’n eksterne protokol keur slegs die opening van die handler goed; dit maak nie die URL-parameters betroubaar nie. Volg die ontvangende app se URL-ontleder tot by enige biblioteek, media-enjin, helper-proses of lêerskryfopsie. Soek ’n navraag-sleutelvoorvoegsel wat URL-velde in stroomaf-opsiename omskakel. Toets beide letterlike en persentasie-geënkodeerde skeidingstekens met ’n onskadelike merker in ’n tydelike rekening.<sup>[[6]](#references)</sup>

Verifieer die **finale opsie wat deur die stroomaf-komponent aanvaar word**, nie net die app se aanvanklike ontleding nie. Een handler het voorvoegsel-navraagsleutels toegelaat om mpv-invoeropdragte te bereik; selfs nadat daardie opsie geblokkeer is, het ’n lêerskryfroete oorgebly. Toets die bereikbare opsieklas, nie net een bekende gevaarlike sleutel nie.<sup>[[7]](#references)</sup>

### Ingeboude `applescript://`-handler

Die `applescript://com.apple.scripteditor` URL-handler aanvaar `action=new` en ’n URL-geënkodeerde `script`-parameter. ’n Blaaierskakel kan dus Script Editor oopmaak met AppleScript wat deur ’n aanvaller beheer word reeds in die redigeerder, sonder dat ’n Terminal-plakstap nodig is. Dit is **nie outomatiese uitvoering nie**: die blaaier kan vra of Script Editor oopgemaak moet word, en die gebruiker moet die skrip uitvoer.<sup>[[8]](#references)</sup>

Onlangse macOS-weergawes kan ’n waarskuwing vir skripdokumente byvoeg, terwyl XProtect AppleScript tydens uitvoering skandeer.<sup>[[8]](#references)[[9]](#references)</sup>

Gebruik ’n onskadelike plaaslike toets om die handler en aanwysings op die macOS-vrystelling wat beoordeel word, na te gaan; dit behoort slegs die redigeerder te vul totdat **Run** geklik word.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

As jou doel passiewe kode-uitvoering is deur bloot na 'n vouer te blaai of 'n lêer te kies, kyk ook na die toegewyde bladsy oor [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), aangesien dit 'n ander, maar nou verwante lêerhanteerder-oppervlak is.



## References

- [1] [Objective-See - Afstandelike Mac-uitbuiting via pasgemaakte URL-skemas](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Om die hek te omseil: 'n nader kyk na Gatekeeper-foute op macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Hoe macOS 'n lêer in die korrekte app oopmaak](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Beheer van LaunchServices in macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Launch Services-konsepte](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - Navorsing oor IINA URL-skema-opdraguitvoering](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Onveilige hantering van mpv-opsies in die URL-skema](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - ClickFix-tegniek gebruik Script Editor in plaas van Terminal](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Terminal- en scriptbeskerming](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
