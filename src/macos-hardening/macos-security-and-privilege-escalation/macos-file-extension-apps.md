# Vishikizo vya programu vya viendelezi vya faili na taratibu za URL katika macOS

{{#include ../../banners/hacktricks-training.md}}

## Hifadhidata ya LaunchServices

Hii ni hifadhidata ya programu zote zilizosakinishwa katika macOS, ambayo inaweza kuulizwa ili kupata taarifa kuhusu kila programu iliyosakinishwa, kama vile **taratibu za URL**, **aina za hati**, **UTI**, na vishikizo chaguomsingi.

Inawezekana kutupa maudhui ya hifadhidata hii kwa:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Au kutumia zana [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ndiyo kiini cha database. Inatoa **huduma kadhaa za XPC** kama `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, na nyinginezo. Lakini pia **inahitaji applications ziwe na entitlements fulani** ili ziweze kutumia utendaji wa XPC unaotolewa, kama `.launchservices.changedefaulthandler` au `.launchservices.changeurlschemehandler` ili kubadilisha apps chaguomsingi za aina za MIME au schemes za URL, na nyinginezo.

**`/System/Library/CoreServices/launchservicesd`** hutangaza huduma `com.apple.coreservices.launchservicesd`, ambayo inaweza kuulizwa ili kupata maelezo kuhusu applications zinazoendeshwa. Inaweza kuulizwa kwa kutumia zana ya mfumo **`/usr/bin/lsappinfo`** au [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Kwa mtazamo wa operator, kumbuka kwamba kwa kawaida kuna **mitazamo miwili yenye manufaa**:

- **Database ya usajili** inayosimamiwa na LaunchServices / `lsd` (inayotumia faili za `.csstore`).
- **Mipangilio chaguomsingi inayotumika kwa kila mtumiaji** iliyohifadhiwa kwenye `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, ndani ya array ya `LSHandlers`.

Tofauti hii ni muhimu: application inaweza kuwa **imesajiliwa** kuwa inaweza kushughulikia aina au scheme fulani, lakini **chaguomsingi la sasa** bado linaweza kuwa bundle ID nyingine.

Katika matoleo ya hivi karibuni ya macOS, ugunduzi wa usajili hauishii kwenye `/Applications`: apps zilizo kwenye folda nyingine zinazoonekana kwa Spotlight na zinazoweza kufikiwa, pamoja na volumes zilizowekwa au kushirikiwa, zinaweza kuingia kwenye registry. Kwa hiyo, wakati wa triage hifadhi maelezo ya `path` na volume kutoka `lsregister -dump`, na usidhani kuwa kusajili app nje ya mfumo kutadumu wakati bundle hiyo bado inaweza kugunduliwa.<sup>[[4]](#references)</sup>

## Vishughulikiaji vya apps vya File Extension na URL scheme

Mstari ufuatao unaweza kusaidia kupata applications zinazoweza kufungua faili kulingana na extension:

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

## Kuhesabu washughulikiaji wanaotumika

Faili muhimu zaidi kwa **mipangilio chaguomsingi ya mtumiaji wa sasa** kwa kawaida ni:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Ili kudump **URL scheme** handlers kutoka kwayo:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Ili kufanya dump ya handlers za **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Ili kubaini mti wa UTI wa faili ya sampuli:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

Ikiwa unataka CLI iliyo rahisi kutumia zaidi kuuliza au kubadilisha mipangilio chaguomsingi:

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

Uamuzi wa handler pia una safu **maalum kwa faili**. Kabla ya kutumia UTI ya faili na chaguomsingi la jumla la mtumiaji, LaunchServices hukagua sifa iliyopanuliwa ya `com.apple.LaunchServices.OpenWith`. Finder huiunda chaguo la **Always Open With** linapochaguliwa kwa faili moja; thamani yake ni binary property list yenye njia ya programu, kitambulishi cha bundle, na kichaguzi cha toleo.<sup>[[3]](#references)</sup>

Ikague na uifafanue bila kutegemea kiendelezi cha jina la faili:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Hii ni muhimu wakati chambo kimoja kinafunguka kwa programu isiyotarajiwa, ingawa `duti`, `dutix`, au `LSHandlers` inaonyesha chaguomsingi ya jumla isiyo na madhara. Kwa maabara inayodhibitiwa, thamani halisi isiyo wazi inaweza kunakiliwa kutoka kwenye faili iliyosanidiwa kupitia Finder; kuifuta hurejesha utatuzi wa kawaida unaotegemea aina:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Vifunguo vya Info.plist vinavyovutia

Wakati wa kufanya uchunguzi wa awali wa application bundle, vifunguo hivi ni muhimu zaidi:

- **`CFBundleDocumentTypes`**: makundi ya nyaraka ambayo bundle inadai inaweza kufungua.
- **`LSItemContentTypes`**: njia **ya kisasa/inayopendekezwa** ya kuunganisha aina za nyaraka na UTIs.
- **`LSHandlerRank`**: mpangilio unaotumiwa na LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: mifumo maalum ya URI inayotekelezwa na app.
- **`UTExportedTypeDeclarations`**: UTIs ambazo app **inamiliki**.
- **`UTImportedTypeDeclarations`**: UTIs ambazo app haimiliki lakini inataka mfumo uzitambue.

Amri muhimu ya kufanya uchunguzi wa haraka ni:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Maelezo ya offensive

Programu hazihitaji kuendeshwa ili zivutie. Bundle ya `.app` iliyowekwa au kunakiliwa inaweza **kuchanganuliwa kiotomatiki na `lsd` mara tu inapoandikwa kwenye diski**, na aina za hati / URL schemes ilizotangaza zinaweza kusajiliwa bila mtumiaji kuwahi kuzindua bundle hiyo.

Hii ni muhimu kwa **utafiti wa persistence / hijacking** na pia kwa **minyororo ya initial-access**:

- Programu hasidi inaweza kudai **extension adimu** au **UTI maalum** na kusubiri mwathiriwa afungue faili ya chambo.
- Programu hasidi inaweza kusajili **URL scheme maalum** inayoweza kufikiwa kutoka kwa browser, programu ya Electron, hati ya office, chat client, au programu nyingine saidizi.<sup>[[1]](#references)</sup>
- Ili kutenganisha utatuzi wa kawaida wa default na kujaribu handler fulani, ita scheme kupitia LaunchServices kwa `open 'targetscheme://host/path?value=test'`, kisha elekeza kwa bundle maalum iliyosajiliwa kwa `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Hii ni muhimu kwa kukagua jinsi programu inayopokea inavyothibitisha na kufungua vipengele vya URL vinavyodhibitiwa na mshambuliaji.<sup>[[1]](#references)</sup>
- Ukihariri app bundle baada ya kuijenga, unaweza kulazimisha LaunchServices ichanganue upya kwa:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Unapojaribu bundles zinazotia shaka, zingatia hasa:

- **`LSHandlerRank=Owner`** kwa aina zisizo za kawaida.
- **Array za `CFBundleDocumentTypes`** pana zinazodai kushughulikia viendelezi vingi.
- **Apps saidizi / wrapper** ambazo tabia yake pekee ya kuvutia hupatikana kupitia document au URI handler.
- **Faili zinazofanana na njia za mkato** (`.webloc`, `.inetloc`, `.fileloc`) ambazo huishia kuelekezwa kupitia LaunchServices. Kwa hila za aina ya `.fileloc` na mambo yanayohusiana na Gatekeeper, angalia [ukurasa huu mwingine](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Ikiwa lengo lako ni code-execution ya kimyakimya kwa kuvinjari tu folda au kuchagua faili, angalia pia ukurasa maalumu kuhusu [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), kwa kuwa hiyo ni sehemu tofauti lakini inayohusiana kwa karibu ya kushughulikia faili.



## References

- [1] [Objective-See - Udukuzi wa mbali wa Mac kupitia custom URL schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Kupita Gate: Uchunguzi wa karibu wa dosari za Gatekeeper kwenye macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Jinsi macOS hufungua faili kwenye app sahihi](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Kudhibiti LaunchServices katika macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
