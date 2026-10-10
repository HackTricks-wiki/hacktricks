# Blaaierartefakte

{{#include ../../../banners/hacktricks-training.md}}

## Blaaierartefakte <a href="#id-3def" id="id-3def"></a>

Blaaierartefakte sluit verskillende soorte data in wat deur webblaaiers gestoor word, soos navigasiegeskiedenis, boekmerke en kasdata. Hierdie artefakte word in spesifieke vouers binne die bedryfstelsel gehou. Die ligging en naam daarvan verskil tussen blaaiers, maar hulle stoor oor die algemeen soortgelyke soorte data.

Hier is ’n opsomming van die algemeenste blaaierartefakte:

- **Navigasiegeskiedenis**: Hou rekord van webwerwe wat die gebruiker besoek het; nuttig om besoeke aan kwaadwillige webwerwe te identifiseer.
- **Outovoltooi-data**: Voorstelle gebaseer op gereelde soektogte; bied insigte wanneer dit saam met navigasiegeskiedenis gebruik word.
- **Boekmerke**: Webwerwe wat deur die gebruiker gestoor is vir vinnige toegang.
- **Uitbreidings en byvoegings**: Blaaieruitbreidings of byvoegings wat deur die gebruiker geïnstalleer is.
- **Kas**: Stoor webinhoud (bv. beelde, JavaScript-lêers) om die laaityd van webwerwe te verbeter; waardevol vir forensiese ontleding.
- **Aantekeninge**: Gestoorde aanmeldbesonderhede.
- **Favicons**: Ikone wat met webwerwe geassosieer word en in oortjies en boekmerke verskyn; nuttig vir bykomende inligting oor gebruikersbesoeke.
- **Blaaiersessies**: Data wat verband hou met oop blaaiersessies.
- **Aflaaie**: Rekords van lêers wat deur die blaaier afgelaai is.
- **Vormdata**: Inligting wat in webvorms ingevoer is en vir toekomstige outovoltooi-voorstelle gestoor is.
- **Kleinkiekies**: Voorskoubeelde van webwerwe.
- **Custom Dictionary.txt**: Woorde wat die gebruiker by die blaaier se woordeboek gevoeg het.

## Firefox

Firefox organiseer gebruikersdata in profiele wat op spesifieke plekke gestoor word, afhangend van die bedryfstelsel:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

’n `profiles.ini`-lêer in hierdie gidse lys die gebruikersprofiele. Elke profiel se data word gestoor in ’n vouer met die naam wat in die `Path`-veranderlike binne `profiles.ini` verskyn. Die lêer is in dieselfde gids as `profiles.ini` self. As ’n profiel se vouer ontbreek, is dit dalk uitgevee.

In elke profielvouer is daar verskeie belangrike lêers:<sup>[[1]](#references)</sup>

- **places.sqlite**: Stoor geskiedenis, boekmerke en aflaaie. Gereedskap soos [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) op Windows kan toegang tot die geskiedenisdata verkry.
  - Gebruik spesifieke SQL-navrae om geskiedenis- en aflaai-inligting te onttrek.
- **bookmarkbackups**: Bevat rugsteunkopieë van boekmerke.
- **formhistory.sqlite**: Stoor webvormdata.
- **handlers.json**: Bestuur protokolhanteerders.
- **persdict.dat**: Pasgemaakte woordeboekwoorde.
- **addons.json** en **extensions.sqlite**: Inligting oor geïnstalleerde byvoegings en uitbreidings.
- **cookies.sqlite**: Koekieberging; [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) is beskikbaar om dit op Windows te inspekteer.
- **cache2/entries** of **startupCache**: Kasdata, toeganklik met gereedskap soos [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Stoor favicons.
- **prefs.js**: Gebruikerinstellings en -voorkeure.
- **downloads.sqlite**: Ouer aflaaidatabasis, nou in places.sqlite geïntegreer.
- **thumbnails**: Kleinkiekies van webwerwe.
- **logins.json**: Geënkripteerde aanmeldinligting.
- **key4.db** of **key3.db**: Stoor enkripsiesleutels om sensitiewe inligting te beskerm.

Daarbenewens kan jy die blaaier se teen-phishing-instellings nagaan deur na `browser.safebrowsing`-inskrywings in `prefs.js` te soek. Dit dui aan of veilige blaaierkenmerke geaktiveer of gedeaktiveer is.<sup>[[2]](#references)</sup>

Om gestoorde aanmeldings uit ’n toeganklike profiel te dekripteer, moet die [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), indien dit opgestel is, verskaf of afsonderlik herwin word; die profiel openbaar nie daardie wagwoord nie. Bevestig dat enige herwonne aanmelding toegang tot sy webrekening verleen. Unix-worteltoegang vereis afsonderlike bewys dat die aanmeldbesonderhede ook deur Unix-verifikasie vir root aanvaar word. Jy kan gestoorde aanmeldings met [firefox_decrypt](https://github.com/unode/firefox_decrypt) nagaan. Die volgende voorbeeld toets kandidaat-Primary Passwords uit ’n wagwoordlêer:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Blaaierartefakte - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome stoor gebruikersprofiele op spesifieke plekke, afhangend van die bedryfstelsel:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Die meeste gebruikersdata kan binne hierdie gidse in die **Default/**- of **ChromeDefaultData/**-vouers gevind word. Die volgende lêers bevat belangrike data:<sup>[[1]](#references)</sup>

- **Geskiedenis**: Bevat URL's, aflaaie en soeksleutelwoorde. Op Windows kan [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) gebruik word om die geskiedenis te lees. Die "Transition Type"-kolom het verskeie betekenisse, insluitend gebruikersklikke op skakels, getikte URL's, vormindienings en bladsyherlaaie.
- **Koekies**: Stoor koekies. [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) is beskikbaar om dit te ondersoek.
- **Kasgeheue**: Bevat data in die kasgeheue. Windows-gebruikers kan [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) gebruik om dit te ondersoek.

  Electron-gebaseerde rekenaartoepassings (bv. Discord) gebruik ook Chromium Simple Cache en laat uitgebreide artefakte op die skyf agter. Sien:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Boekmerke**: Gebruiker se boekmerke.
- **Web Data**: Bevat vormgeskiedenis.
- **Favicons**: Stoor webwerf-favicons.
- **Login Data**: Bevat aanmeldbewyse soos gebruikersname en wagwoorde.
- **Current Session**/**Current Tabs**: Data oor die huidige blaaisessie en oop oortjies.
- **Last Session**/**Last Tabs**: Inligting oor die webwerwe wat aktief was tydens die laaste sessie voordat Chrome gesluit is.
- **Uitbreidings**: Gidse vir blaaieruitbreidings en byvoegings.
- **Kleinkiekies**: Stoor webwerf-kleinkiekies.
- **Preferences**: 'n Lêer met baie inligting, insluitend instellings vir inproppe, uitbreidings, opspringvensters, kennisgewings en meer.
- **Blaaier se ingeboude anti-phishing**: Voer `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` uit om te kyk of anti-phishing- en wanwarebeskerming geaktiveer is. Soek vir `{"enabled: true,"}` in die uitvoer.<sup>[[2]](#references)</sup>

'n Chromium-profiel se `Local Extension Settings/<extension-id>/`-gids kan plaaslike toestand vir uitbreidings bevat, insluitend sleutelmateriale vir wagwoordbestuurders. Passbolt sê byvoorbeeld dat sy geënkripteerde private sleutel in die plaaslike berging van die blaaieruitbreiding gehou word (https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), en sy [Chrome-uitbreiding-ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) identifiseer die betrokke gids. Die teenwoordigheid van die gids bewys nie op sigself dat 'n sleutel daar is of ontsluit 'n kluis nie: die gebruiker moet toegang hê tot die profieldata, 'n bruikbare private sleutel en wagwoordfrase, en 'n gemagtigde herstel-/verifikasieroete na die bediener. 'n Kluisitem wat 'n bedryfstelselrekening se wagwoord bevat, vereis afsonderlike verifikasie dat die rekening hergebruik word. Roetine-enumerasie behoort slegs die bergingpad aan te meld, sonder om die LevelDB-lêers of geheime waardes daarvan uit te stort.

## **SQLite DB-dataherwinning**

Soos jy in die vorige afdelings kan sien, gebruik beide Chrome en Firefox **SQLite**-databasisse om data te stoor. Dit is moontlik om **verwyderde inskrywings te herwin met die hulpmiddel** [**sqlparse**](https://github.com/padfoot999/sqlparse) **of** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 bestuur sy data en metadata oor verskeie liggings, wat help om gestoorde inligting en die besonderhede daarvan te skei sodat dit maklik verkry en bestuur kan word.

### Metadataberging

Metadata vir Internet Explorer word in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` gestoor (waar VX V01, V16 of V24 is). Die `V01.log`-lêer kan verskille in wysigingstye met `WebcacheVX.data` toon, wat aandui dat herstel met `esentutl /r V01 /d` nodig kan wees. Hierdie metadata, wat in 'n ESE-databasis gehuisves word, kan onderskeidelik met hulpmiddels soos photorec en [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) herwin en ondersoek word. In die **Containers**-tabel kan jy vasstel in watter spesifieke tabelle of houers elke datasegment gestoor word, insluitend kasbesonderhede vir ander Microsoft-hulpmiddels soos Skype.

### Ondersoek van kasgeheue

Die [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html)-hulpmiddel laat jou toe om die kasgeheue te ondersoek; die ligging van die vouer waarin kasdata onttrek is, word vereis. Metadata vir die kasgeheue sluit die lêernaam, gids, toegangstelling, URL-oorsprong en tydstempels in wat die skeppings-, toegangs-, wysigings- en vervaltye van die kas aandui.

### Koekiebestuur

Koekies kan met [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) ondersoek word. Metadata sluit name, URL's, toegangstellings en verskeie tydverwante besonderhede in. Permanente koekies word in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gestoor, terwyl sessiekoekies in die geheue bly.

### Aflaaibesonderhede

Aflaai-metadata is via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) toeganklik, met spesifieke houers wat data soos URL, lêertipe en aflaaiplek bevat. Fisiese lêers kan gevind word in `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Blaaigeskiedenis

Gebruik [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) om die blaaigeskiedenis te hersien. Die ligging van die onttrekte geskiedenislêers en die Internet Explorer-konfigurasie word vereis. Die metadata hier sluit wysigings- en toegangstye, asook toegangstellings, in. Geskiedenislêers is in `%userprofile%\Appdata\Local\Microsoft\Windows\History` geleë.

### Getikte URL's

Getikte URL's en die tye waarop hulle gebruik is, word in die register onder `NTUSER.DAT` by `Software\Microsoft\InternetExplorer\TypedURLs` en `Software\Microsoft\InternetExplorer\TypedURLsTime` gestoor. Dit hou rekord van die laaste 50 URL's wat deur die gebruiker ingevoer is en die tye waarop hulle laas ingevoer is.

## Microsoft Edge

Microsoft Edge stoor gebruikersdata in `%userprofile%\Appdata\Local\Packages`. Die paaie vir verskillende datatipes is:<sup>[[1]](#references)</sup>

- **Profielpad**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Geskiedenis, koekies en aflaaie**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Instellings, boekmerke en leeslys**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Kasgeheue**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Laaste aktiewe sessies**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-data word by `/Users/$User/Library/Safari` gestoor. Belangrike lêers sluit in:<sup>[[3]](#references)</sup>

- **History.db**: Bevat `history_visits`- en `history_items`-tabelle met URL's en besoektydstempels. Gebruik `sqlite3` om navrae uit te voer.
- **Downloads.plist**: Inligting oor afgelaaide lêers.
- **Bookmarks.plist**: Stoor URL's van boekmerke.
- **TopSites.plist**: Webwerwe wat die meeste besoek word.
- **Extensions.plist**: Lys van Safari-blaaieruitbreidings. Gebruik `plutil` of `pluginkit` om dit te verkry.
- **UserNotificationPermissions.plist**: Domeine wat toegelaat word om stootkennisgewings te stuur. Gebruik `plutil` om dit te ontleed.
- **LastSession.plist**: Oortjies van die laaste sessie. Gebruik `plutil` om dit te ontleed.
- **Blaaier se ingeboude anti-phishing**: Kontroleer met `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. 'n Antwoord van 1 dui aan dat die funksie aktief is.<sup>[[2]](#references)</sup>

## Opera

Opera se data is in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` geleë en gebruik dieselfde formaat as Chrome vir geskiedenis en aflaaie.

- **Blaaier se ingeboude anti-phishing**: Verifieer met `grep` of `fraud_protection_enabled` in die Preferences-lêer op `true` gestel is.<sup>[[2]](#references)</sup>

Hierdie paaie en opdragte is noodsaaklik om toegang te verkry tot die blaaidata wat deur verskillende webblaaiers gestoor word en dit te verstaan.

## References

- [1] [Webblaaiers-forensika: 'n Gids vir forensiese ontleding van webblaaiers](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS-voorvalreaksie | Deel 3: Stelselmanipulasie](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X-voorvalreaksie: Skriptering en ontleding deur Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
