# Vidhibiti vya programu vya viendelezi vya faili na URL scheme kwenye macOS

{{#include ../../banners/hacktricks-training.md}}

## Hifadhidata ya LaunchServices

Hii ni hifadhidata ya programu zote zilizosakinishwa kwenye macOS. Inaweza kuulizwa ili kupata maelezo kuhusu kila programu iliyosakinishwa, kama vile **URL schemes**, **aina za hati**, **UTIs**, na vidhibiti chaguomsingi.

Inawezekana kutoa data kutoka kwenye hifadhidata hii kwa:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Au kutumia zana [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ndiyo kiini cha hifadhidata. Inatoa **huduma kadhaa za XPC** kama `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, na nyinginezo. Lakini pia **inahitaji baadhi ya entitlements** ili programu ziweze kutumia utendakazi wa XPC unaotolewa, kama `.launchservices.changedefaulthandler` au `.launchservices.changeurlschemehandler` za kubadilisha programu chaguomsingi za aina za MIME au URL schemes, na nyinginezo.

**`/System/Library/CoreServices/launchservicesd`** hudai huduma ya `com.apple.coreservices.launchservicesd` na inaweza kuulizwa ili kupata taarifa kuhusu programu zinazoendeshwa. Inaweza kuulizwa kwa kutumia zana ya mfumo **`/usr/bin/lsappinfo`** au [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Kwa mtazamo wa operator, kumbuka kwamba kwa kawaida kuna **mitazamo miwili muhimu**:

- **Hifadhidata ya usajili** inayosimamiwa na LaunchServices / `lsd` (na kuhifadhiwa katika faili za `.csstore`).
- **Mipangilio chaguomsingi inayotumika kwa kila mtumiaji** iliyohifadhiwa katika `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` ndani ya safu ya `LSHandlers`.

Tofauti hii ni muhimu: programu inaweza **kusajiliwa** kuwa inaweza kushughulikia aina au scheme fulani, lakini **chaguomsingi la sasa** bado linaweza kuwa bundle ID nyingine.

Katika matoleo ya hivi karibuni ya macOS, ugunduzi wa usajili hauishii kwenye `/Applications`: programu katika folda nyingine zinazoonekana kwenye Spotlight na zinazoweza kufikiwa, pamoja na volumes zilizowekwa au za pamoja, zinaweza kuongezwa kwenye registry. Kwa hivyo, wakati wa uchunguzi, hifadhi taarifa za `path` na volume kutoka `lsregister -dump`, na usidhani kuwa kuondoa usajili wa programu kutadumu wakati bundle bado inaweza kugunduliwa.<sup>[[4]](#references)</sup>

## Vishughulikiaji vya programu vya viendelezi vya faili na URL scheme

Mstari ufuatao unaweza kusaidia kupata programu zinazoweza kufungua faili kulingana na kiendelezi:

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

## Kuorodhesha handlers zinazotumika

Faili muhimu zaidi kwa **mipangilio chaguomsingi ya mtumiaji wa sasa** kwa kawaida ni:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Ili kufanya dump ya **URL scheme** handlers kutoka humo:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Ili kutoa handlers za **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Ili kubaini mti wa UTI wa faili ya sampuli:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

Ikiwa unataka CLI iliyo rahisi kutumia zaidi kuuliza kuhusu au kubadilisha mipangilio chaguomsingi:

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

### Ubatilishaji wa `Open With` kwa kila faili

Utatuzi wa handler pia una safu **maalum kwa faili**. Kabla ya kutumia UTI ya faili na chaguo-msingi la jumla la mtumiaji, LaunchServices hukagua sifa iliyopanuliwa ya `com.apple.LaunchServices.OpenWith`. Finder huitengeneza unapochagua **Always Open With** kwa faili moja; thamani yake ni orodha ya sifa ya binary iliyo na njia ya programu, kitambulisho cha bundle na kiteuzi cha toleo.<sup>[[3]](#references)</sup>

Ikague na kuisimbua bila kuamini kiendelezi cha jina la faili:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Hii ni muhimu wakati chambo kimoja kinafungua programu isiyotarajiwa, ingawa `duti`, `dutix`, au `LSHandlers` zinaonyesha chaguo-msingi salama la jumla. Kwa maabara inayodhibitiwa, thamani halisi isiyoeleweka inaweza kunakiliwa kutoka kwenye faili iliyosanidiwa kupitia Finder; kuifuta hurejesha utatuzi wa kawaida kulingana na aina:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Vifunguo Muhimu vya Info.plist

Unapochunguza kifurushi cha programu, vifunguo hivi ni muhimu zaidi:

- **`CFBundleDocumentTypes`**: makundi ya hati ambayo kifurushi kinadai kinaweza kufungua.
- **`LSItemContentTypes`**: njia **ya kisasa / inayopendelewa** ya kuunganisha aina za hati na UTIs.
- **`LSHandlerRank`**: kiwango kinachotumiwa na LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes zinazotekelezwa na programu.
- **`UTExportedTypeDeclarations`**: UTIs ambazo programu **inamiliki**.
- **`UTImportedTypeDeclarations`**: UTIs ambazo programu haimiliki lakini inataka mfumo uzitambue.

Amri muhimu ya uchunguzi wa haraka ni:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Jambo dogo lakini muhimu: ikiwa **`LSItemContentTypes`** ipo, key za zamani kama **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, na **`CFBundleTypeOSTypes`** kimsingi ni data za uoanifu wa legacy. Katika utatuzi halisi wa handler, anza kwa kuangalia njia ya UTI.

## Maelezo ya upande wa mashambulizi

Programu hazihitaji kuendeshwa ili madai yake ya kuwa handler yawe ya kuvutia, lakini **kuandika `.app` bundle pekee hakuhakikishi usajili wa mara moja**. Finder inaweza kusajili programu inapoigundua, ikiwemo mtumiaji anapovinjari folda yake; usajili unaweza pia kutokea wakati wa kuwasha au kuingia, au kupitia mwito wa usajili ulio wazi. Angalia `lsregister -dump` kabla ya kujaribu dai hilo. Usajili pekee hauzindui programu wala kuifanya iwe default inayotumika.<sup>[[5]](#references)</sup> Kwa masharti ya awali ya persistence, angalia [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Hili linafaa kwa **utafiti wa persistence / hijacking** na kwa **minyororo ya initial-access**:

- Programu hasidi inaweza kudai **extension isiyotumika sana** au **custom UTI**, kisha kusubiri mwathiriwa afungue faili ya chambo.
- Programu hasidi inaweza kusajili **custom URL scheme** inayoweza kufikiwa kupitia browser, programu ya Electron, hati ya office, chat client au programu nyingine ya helper.<sup>[[1]](#references)</sup>
- Ili kutenganisha utatuzi wa kawaida wa default na kujaribu handler fulani, tumia LaunchServices kuita scheme kwa `open 'targetscheme://host/path?value=test'`, kisha lenga bundle maalum iliyosajiliwa kwa `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Hii ni muhimu kwa kukagua jinsi programu inayopokea inavyothibitisha na decode vipengele vya URL vinavyodhibitiwa na mshambuliaji.<sup>[[1]](#references)</sup>
- Ukihariri app bundle baada ya kuijenga, unaweza kulazimisha LaunchServices kuichanganua upya kwa:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Unapojaribu bundles zinazotiliwa shaka, zingatia hasa:

- **`LSHandlerRank=Owner`** kwenye aina zisizo za kawaida.
- Arrays pana za **`CFBundleDocumentTypes`** zinazodai kushughulikia viendelezi vingi.
- Apps za helper / wrapper ambazo tabia yake pekee ya kuvutia hujitokeza kupitia handler ya document au URI.
- Faili zinazofanana na njia za mkato (`.webloc`, `.inetloc`, `.fileloc`) ambazo hatimaye hutuma ombi kwa LaunchServices. Kwa mbinu za aina ya `.fileloc` na mambo yanayohusiana na Gatekeeper, angalia [ukurasa huu mwingine](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### URL parameters zinazopitishwa kwenye options za vipengele vya baadaye

Uthibitisho wa kivinjari wa kufungua external protocol huruhusu tu handler kufunguliwa; hauaminishi URL parameters. Fuatilia URL parser ya app inayopokea hadi kwenye library yoyote, media engine, helper process au option ya kuandika faili. Tafuta prefix ya query key inayogeuza sehemu za URL kuwa majina ya options za vipengele vya baadaye. Jaribu vitenganishi vya kawaida na vilivyosimbwa kwa asilimia, ukitumia marker isiyo na madhara kwenye akaunti ya majaribio.<sup>[[6]](#references)</sup>

Thibitisha **option ya mwisho inayokubaliwa na kipengele cha baadaye**, si uchanganuzi wa awali wa app pekee. Handler moja iliruhusu query keys zenye prefix kufikia amri za ingizo za mpv; hata hivyo, kuzuia option hiyo bado kuliacha njia ya kuandika faili. Jaribu aina ya options zinazoweza kufikiwa, si key moja tu inayojulikana kuwa hatari.<sup>[[7]](#references)</sup>

### Handler ya `applescript://` iliyojengewa ndani

Handler ya URL ya `applescript://com.apple.scripteditor` hukubali `action=new` na parameter ya `script` iliyosimbwa kwa URL. Kwa hiyo, kiungo cha kivinjari kinaweza kufungua Script Editor ikiwa na AppleScript inayodhibitiwa na mshambulizi tayari ndani ya editor, bila kuhitaji hatua ya kubandika kutoka Terminal. **Hii haisababishi utekelezaji wa moja kwa moja**: kivinjari kinaweza kuuliza kama kifungue Script Editor, na mtumiaji lazima aendeshe script.<sup>[[8]](#references)</sup>

Matoleo ya hivi karibuni ya macOS yanaweza kuonyesha onyo la script-document, huku XProtect ikichanganua AppleScript wakati wa utekelezaji.<sup>[[8]](#references)[[9]](#references)</sup>

Tumia jaribio lisilo na madhara la ndani ili kuangalia handler na maulizo kwenye toleo la macOS linalotathminiwa; linapaswa kujaza tu editor hadi **Run** ibofywe.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Ikiwa lengo lako ni kutekeleza code bila hatua ya mtumiaji, kwa kuvinjari tu folda au kuchagua faili, angalia pia ukurasa maalum wa [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), kwa kuwa huo ni uso tofauti lakini unaohusiana kwa karibu wa kushughulikia faili.



## References

- [1] [Objective-See - Kutumia custom URL schemes kufanya remote exploitation ya Mac](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Kupita Gate: Uchunguzi wa karibu wa kasoro za Gatekeeper kwenye macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Jinsi macOS inavyofungua faili kwenye app sahihi](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Kudhibiti LaunchServices kwenye macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Dhana za Launch Services](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - Utafiti wa utekelezaji wa amri kupitia URL scheme ya IINA](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Ushughulikiaji usio salama wa chaguo za mpv kwenye URL scheme yake](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - Mbinu ya ClickFix hutumia Script Editor badala ya Terminal](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Ulinzi wa Terminal na script](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
