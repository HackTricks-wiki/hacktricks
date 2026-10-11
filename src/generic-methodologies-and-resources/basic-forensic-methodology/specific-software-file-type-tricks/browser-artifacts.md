# Blaaierartefakte

{{#include ../../../banners/hacktricks-training.md}}

## Blaaierartefakte <a href="#id-3def" id="id-3def"></a>

Blaaierartefakte sluit verskillende soorte data in wat deur webblaaiers gestoor word, soos blaaigeskiedenis, boekmerke en kasdata. Hierdie artefakte word in spesifieke vouers binne die bedryfstelsel gehou. Die liggings en name verskil tussen blaaiers, maar soortgelyke soorte data word oor die algemeen gestoor.

Hier is ’n opsomming van die mees algemene blaaierartefakte:

- **Blaaigeskiedenis**: Hou gebruikers se webwerfbesoeke dop en is nuttig om besoeke aan kwaadwillige webwerwe te identifiseer.
- **Outovoltooi-data**: Voorstelle gebaseer op gereelde soektogte, wat insigte bied wanneer dit saam met blaaigeskiedenis gebruik word.
- **Boekmerke**: Webwerwe wat deur die gebruiker gestoor is vir vinnige toegang.
- **Uitbreidings en byvoegings**: Blaaieruitbreidings of byvoegings wat deur die gebruiker geïnstalleer is.
- **Kas**: Stoor webinhoud (bv. beelde en JavaScript-lêers) om webwerwe vinniger te laai; dit is waardevol vir forensiese ontleding.
- **Aanmeldings**: Gestoorde aanmeldbewyse.
- **Favicons**: Ikone wat met webwerwe geassosieer word en in oortjies en boekmerke verskyn; nuttig vir bykomende inligting oor gebruikers se besoeke.
- **Blaaiersessies**: Data wat verband hou met oop blaaiersessies.
- **Aflaaie**: Rekords van lêers wat deur die blaaier afgelaai is.
- **Vormdata**: Inligting wat in webvorms ingevoer is en vir toekomstige outovoltooi-voorstelle gestoor is.
- **Duimnaels**: Voorskoubeelde van webwerwe.
- **Custom Dictionary.txt**: Woorde wat deur die gebruiker by die blaaier se woordeboek gevoeg is.

## Firefox

Firefox organiseer gebruikersdata in profiele wat op spesifieke plekke gestoor word, afhangend van die bedryfstelsel:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

’n `profiles.ini`-lêer in hierdie vouers lys die gebruikerprofiele. Elke profiel se data word gestoor in ’n vouer waarvan die naam in die `Path`-veranderlike binne `profiles.ini` aangedui word. Hierdie vouer is in dieselfde gids as `profiles.ini`. As ’n profielvouer ontbreek, is dit moontlik uitgevee.

In elke profielvouer is daar verskeie belangrike lêers:<sup>[[1]](#references)</sup>

- **places.sqlite**: Stoor geskiedenis, boekmerke en aflaaie. Gereedskap soos [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) op Windows kan toegang tot die geskiedenisdata verkry.
  - Gebruik spesifieke SQL-navrae om inligting oor geskiedenis en aflaaie te onttrek.
- **bookmarkbackups**: Bevat rugsteunkopieë van boekmerke.
- **formhistory.sqlite**: Stoor webvormdata.
- **handlers.json**: Bestuur protokolhanteerders.
- **persdict.dat**: Pasgemaakte woordeboekwoorde.
- **addons.json** en **extensions.sqlite**: Inligting oor geïnstalleerde byvoegings en uitbreidings.
- **cookies.sqlite**: Koekieberging; [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) is beskikbaar om dit op Windows te inspekteer.
- **cache2/entries** of **startupCache**: Kasdata, toeganklik met gereedskap soos [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Stoor favicons.
- **prefs.js**: Gebruikerinstellings en voorkeure.
- **downloads.sqlite**: Ouer aflaaidatabasis, nou geïntegreer in places.sqlite.
- **thumbnails**: Webwerwinge-duimnaels.
- **logins.json**: Geënkripteerde aanmeldingsinligting.
- **key4.db** of **key3.db**: Stoor enkripsiesleutels om sensitiewe inligting te beveilig.

Jy kan ook die blaaier se teen-uitvissinginstellings nagaan deur na `browser.safebrowsing`-inskrywings in `prefs.js` te soek. Dit dui aan of veilige-blaaifunksies geaktiveer of gedeaktiveer is.<sup>[[2]](#references)</sup>

Om gestoorde aanmeldings uit ’n toeganklike profiel te dekripteer, moet die [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), indien dit opgestel is, verskaf of afsonderlik herwin word; die profiel verklap nie daardie wagwoord nie. Bevestig dat enige herwinde aanmelding toegang tot sy webrekening verleen. Unix-worteltoegang vereis afsonderlike bewys dat die aanmeldbewys ook vir Unix-verifikasie as wortel aanvaar word. Jy kan gestoorde aanmeldings met [firefox_decrypt](https://github.com/unode/firefox_decrypt) nagaan. Die volgende voorbeeld toets moontlike Primary Passwords uit ’n wagwoordlêer:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Browsers Artifacts - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome stoor gebruikersprofiele op spesifieke plekke, afhangend van die bedryfstelsel:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Die meeste gebruikersdata kan in die **Default/**- of **ChromeDefaultData/**-vouers in hierdie gidse gevind word. Die volgende lêers bevat belangrike data:<sup>[[1]](#references)</sup>

- **History**: Bevat URL's, aflaaie en soekterme. Op Windows kan [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) gebruik word om die geskiedenis te lees. Die "Transition Type"-kolom het verskeie betekenisse, waaronder gebruikers wat op skakels klik, URL's intik, vorms indien en bladsye herlaai.
- **Cookies**: Stoor koekies. [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) is beskikbaar om dit te inspekteer.
- **Cache**: Bevat kasdata. Windows-gebruikers kan [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) gebruik om dit te inspekteer.

  Electron-gebaseerde rekenaartoepassings (bv. Discord) gebruik ook Chromium Simple Cache en laat uitgebreide artefakte op skyf agter. Sien:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Gebruiker se boekmerke.
- **Web Data**: Bevat vormgeskiedenis.
- **Favicons**: Stoor webwerf-favicons.
- **Login Data**: Bevat aanmeldbewyse soos gebruikersname en wagwoorde.
- **Current Session**/**Current Tabs**: Data oor die huidige blaaisessie en oop oortjies.
- **Last Session**/**Last Tabs**: Inligting oor die webwerwe wat aktief was tydens die vorige sessie voordat Chrome gesluit is.
- **Extensions**: Gidse vir blaaieruitbreidings en byvoegings.
- **Thumbnails**: Stoor webwerf-kleinkiekies.
- **Preferences**: 'n Lêer met baie inligting, insluitend instellings vir plugins, uitbreidings, opspringvensters, kennisgewings en meer.
- **Browser’s built-in anti-phishing**: Voer `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` uit om te kyk of anti-phishing- en wanwarebeskerming geaktiveer is. Soek vir `{"enabled: true,"}` in die uitvoer.<sup>[[2]](#references)</sup>

'n Chromium-profiel se `Local Extension Settings/<extension-id>/`-gids kan uitbreiding-plaaslike toestand bevat, insluitend sleutelmateriaal vir wagwoordbestuurders. Passbolt meld byvoorbeeld dat sy geënkripteerde private sleutel in die blaaieruitbreiding se plaaslike berging gehou word, soos beskryf in [Passbolt se dokumentasie](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/). Sy [Chrome-uitbreiding-ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) dui die betrokke gids aan. Die blote teenwoordigheid van die gids bewys nie dat 'n sleutel daar is nie en ontsluit ook nie 'n kluis nie: die gebruiker moet toegang tot die profieldata, 'n bruikbare private sleutel en wagwoordfrase, en 'n gemagtigde herstel- of verifikasieroete na die bediener hê. 'n Kluisitem met 'n wagwoord vir 'n bedryfstelselrekening vereis afsonderlike verifikasie dat die rekening hergebruik word. Roetine-enumerasie behoort slegs die bergingspad aan te meld, sonder om die LevelDB-lêers of geheime waardes daarvan uit te dump.

## **SQLite DB-dataherwinning**

Soos jy in die vorige afdelings kan sien, gebruik beide Chrome en Firefox **SQLite**-databasisse om data te stoor. Dit is moontlik om **geskrapte inskrywings te herwin met die nutsmiddel** [**sqlparse**](https://github.com/padfoot999/sqlparse) **of** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## Internet Explorer 11

Internet Explorer 11 bestuur sy data en metadata op verskeie plekke. Dit help om gestoorde inligting en die ooreenstemmende besonderhede te skei vir maklike toegang en bestuur.

### Metadataberging

Internet Explorer se metadata word gestoor in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (waar VX V01, V16 of V24 is). Die `V01.log`-lêer kan 'n verskil in wysigingstyd met `WebcacheVX.data` toon, wat daarop dui dat herstel met `esentutl /r V01 /d` nodig kan wees. Hierdie metadata word in 'n ESE-databasis gehou en kan met nutsmiddels soos photorec en [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) onderskeidelik herwin en ondersoek word. In die **Containers**-tabel kan jy sien in watter spesifieke tabelle of houers elke datasegment gestoor word, insluitend kasbesonderhede vir ander Microsoft-nutsmiddels soos Skype.

### Kasinspeksie

Die [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html)-nutsmiddel maak inspeksie van die kas moontlik; die ligging van die vouer waarin die kasdata onttrek is, word vereis. Kasmetadata sluit die lêernaam, gids, toegangstelling, URL-oorsprong en tydstempels vir kaskepping, -toegang, -wysiging en -verval in.

### Koekiebestuur

Koekies kan met [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) ondersoek word. Die metadata sluit name, URL's, toegangstellings en verskeie tydverwante besonderhede in. Volgehoue koekies word in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gestoor, terwyl sessiekoekies in die geheue bly.

### Aflaaibesonderhede

Aflaaimetadata is via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) toeganklik; spesifieke houers bevat data soos die URL, lêertipe en aflaaiplek. Fisiese lêers kan gevind word onder `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Blaaigeskiedenis

Gebruik [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) om die blaaigeskiedenis na te gaan. Die ligging van die onttrekte geskiedenislêers moet gespesifiseer word, en Internet Explorer moet daarvoor opgestel word. Die metadata sluit wysigings- en toegangstye, sowel as toegangstellings, in. Geskiedenislêers is in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Getikte URL's

Getikte URL's en die tyd waarop hulle gebruik is, word in die register onder `NTUSER.DAT` gestoor by `Software\Microsoft\InternetExplorer\TypedURLs` en `Software\Microsoft\InternetExplorer\TypedURLsTime`. Dit hou die laaste 50 URL's wat die gebruiker ingevoer het en die laaste invoertyd daarvan by.

## Microsoft Edge

Microsoft Edge stoor gebruikersdata in `%userprofile%\Appdata\Local\Packages`. Die paaie vir verskillende datatipes is:<sup>[[1]](#references)</sup>

- **Profielpad**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Geskiedenis, koekies en aflaaie**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Instellings, boekmerke en leeslys**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Kas**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Laaste aktiewe sessies**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-data word gestoor by `/Users/$User/Library/Safari`. Belangrike lêers sluit in:<sup>[[3]](#references)</sup>

- **History.db**: Bevat die `history_visits`- en `history_items`-tabelle met URL's en besoektydstempels. Gebruik `sqlite3` om navrae uit te voer.
- **Downloads.plist**: Inligting oor afgelaaide lêers.
- **Bookmarks.plist**: Stoor URL's van boekmerke.
- **TopSites.plist**: Die webwerwe wat die meeste besoek word.
- **Extensions.plist**: Lys van Safari-blaaieruitbreidings. Gebruik `plutil` of `pluginkit` om dit op te haal.
- **UserNotificationPermissions.plist**: Domeine wat toegelaat word om stootkennisgewings te stuur. Gebruik `plutil` om dit te ontleed.
- **LastSession.plist**: Oortjies van die vorige sessie. Gebruik `plutil` om dit te ontleed.
- **Browser’s built-in anti-phishing**: Kontroleer met `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. 'n Antwoord van 1 dui aan dat die funksie aktief is.<sup>[[2]](#references)</sup>

## Opera

Opera se data is geleë in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` en gebruik dieselfde formaat as Chrome vir geskiedenis en aflaaie.

- **Browser’s built-in anti-phishing**: Kontroleer met `grep` of `fraud_protection_enabled` in die Preferences-lêer op `true` gestel is.<sup>[[2]](#references)</sup>

Hierdie paaie en opdragte is noodsaaklik om toegang te verkry tot die blaaidata wat deur verskillende webblaaiers gestoor word en dit te verstaan.

## References

- [1] [Forensiese ondersoek van webblaaiers: 'n Gids tot forensiese ontleding van webblaaiers](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS-insidentreaksie | Deel 3: Stelselmanipulasie](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X-insidentreaksie: Skriptering en ontleding deur Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
