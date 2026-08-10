# Blaaierartefakte

## Blaaierartefakte <a href="#id-3def" id="id-3def"></a>

Blaaierartefakte sluit verskeie tipes data in wat deur webblaaiers gestoor word, soos navigasiegeskiedenis, boekmerke en kasdata. Hierdie artefakte word in spesifieke vouers binne die bedryfstelsel gehou. Die ligging en naam verskil tussen blaaiers, maar hulle stoor oor die algemeen soortgelyke datatipes.

Hier is 'n opsomming van die algemeenste blaaierartefakte:

- **Navigasiegeskiedenis**: Hou gebruikers se besoeke aan webwerwe dop en is nuttig om besoeke aan kwaadwillige webwerwe te identifiseer.
- **Outovoltooi-data**: Voorstelle gebaseer op gereelde soektogte, wat insigte bied wanneer dit met navigasiegeskiedenis gekombineer word.
- **Boekmerke**: Webwerwe wat deur die gebruiker gestoor is vir vinnige toegang.
- **Uitbreidings en byvoegings**: Blaaieruitbreidings of byvoegings wat deur die gebruiker geïnstalleer is.
- **Kas**: Stoor webinhoud (bv. beelde, JavaScript-lêers) om die laaitye van webwerwe te verbeter en is waardevol vir forensiese ontleding.
- **Aanmeldings**: Gestoorde aanmeldbewyse.
- **Favicons**: Ikone wat met webwerwe geassosieer word en in oortjies en boekmerke verskyn; nuttig vir bykomende inligting oor gebruikersbesoeke.
- **Blaaiersessies**: Data wat met oop blaaiersessies verband hou.
- **Aflaaie**: Rekords van lêers wat deur die blaaier afgelaai is.
- **Vormdata**: Inligting wat in webvorms ingevoer is en vir toekomstige outovolt voorstelings gestoor word.
- **Duimnaels**: Voorskoubeelde van webwerwe.
- **Custom Dictionary.txt**: Woorde wat deur die gebruiker by die blaaier se woordeboek gevoeg is.

## Firefox

Firefox organiseer gebruikersdata binne profiele wat in spesifieke liggings gestoor word, gebaseer op die bedryfstelsel:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

'n `profiles.ini`-lêer binne hierdie gidse lys die gebruikerprofiele. Elke profiel se data word gestoor in 'n vouer met 'n naam wat in die `Path`-veranderlike binne `profiles.ini` aangedui word, en wat in dieselfde gids as `profiles.ini` self geleë is. As 'n profiel se vouer ontbreek, is dit moontlik dat dit verwyder is.

Binne elke profielvouer kan jy verskeie belangrike lêers vind:<sup>[[1]](#references)</sup>

- **places.sqlite**: Stoor geskiedenis, boekmerke en aflaaie. Tools soos [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) op Windows kan toegang tot die geskieden data verkry.
- Gebruik spesifieke SQL queries om geskiedenis- en aflaai-inligting te onttrek.
- **bookmarkbackups**: Bevat rugsteunkopieë van boekmerke.
- **formhistory.sqlite**: Stoor webvormdata.
- **handlers.json**: Bestuur protokolhanters.
- **persdict.dat**: Pasgemaakte woordeboekwoorde.
- **addons.json** en **extensions.sqlite**: Inligting oor geïnstalleerde byvoegings en uitbreidings.
- **cookies.sqlite**: Koekieberging, met [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) beskikbaar vir inspeksie op Windows.
- **cache2/entries** of **startupCache**: Kasdata, toeganklik deur tools soos [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Stoor favicons.
- **prefs.js**: Gebruikerinstellings en -voorkeure.
- **downloads.sqlite**: Ouer aflaaidatabasis, wat nou by places.sqlite geïntegreer is.
- **thumbnails**: Duimnaels van webwerwe.
- **logins.json**: Geënkripteerde aanmeldinligting.
- **key4.db** of **key3.db**: Stoor enkripsiesleutels om sensitiewe inligting te beveilig.

Daarbenewens kan die blaaier se anti-phishing-instellings nagegaan word deur na `browser.safebrowsing`-inskrywings in `prefs.js` te soek. Dit dui aan of veilige-blaaikenmerke geaktiveer of gedeaktiveer is.<sup>[[2]](#references)</sup>

Om te probeer om die hoofwagwoord te dekripteer, kan jy [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) gebruik\
Met die volgende script en oproep kan jy 'n wagwoordlêer spesifiseer om te brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Blaaiersartefakte - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome stoor gebruikersprofiele op spesifieke liggings gebaseer op die bedryfstelsel:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Binne hierdie gidse kan die meeste gebruikersdata in die **Default/**- of **ChromeDefaultData/**-vouers gevind word. Die volgende lêers bevat belangrike data:<sup>[[1]](#references)</sup>

- **History**: Bevat URL's, downloads en soeksleutelwoorde. Op Windows kan [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) gebruik word om die geskiedenis te lees. Die "Transition Type"-kolom het verskeie betekenisse, insluitend gebruikersklikke op skakels, ingetikte URL's, vormindienings en bladsyherlaaie.
- **Cookies**: Stoor cookies. Vir inspeksie is [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) beskikbaar.
- **Cache**: Bevat gekasde data. Om dit te inspekteer, kan Windows-gebruikers [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) gebruik.

Electron-gebaseerde desktop-apps (bv. Discord) gebruik ook Chromium Simple Cache en laat uitgebreide skyf-artefakte agter. Sien:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Gebruikerboekmerke.
- **Web Data**: Bevat vormgeskiedenis.
- **Favicons**: Stoor webwerf-favicons.
- **Login Data**: Sluit aanmeldbewyse soos gebruikersname en wagwoorde in.
- **Current Session**/**Current Tabs**: Data oor die huidige blaaisessie en oop oortjies.
- **Last Session**/**Last Tabs**: Inligting oor die werwe wat tydens die vorige sessie aktief was voordat Chrome gesluit is.
- **Extensions**: Gidse vir blaaieruitbreidings en addons.
- **Thumbnails**: Stoor webwerf-kleinkiekies.
- **Preferences**: 'n Lêer ryk aan inligting, insluitend instellings vir plugins, uitbreidings, pop-ups, kennisgewings en meer.
- **Browser’s built-in anti-phishing**: Om te kontroleer of anti-phishing- en malware-beskerming geaktiveer is, voer `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` uit. Soek vir `{"enabled: true,"}` in die uitvoer.<sup>[[2]](#references)</sup>

## **SQLite DB-dataherwinning**

Soos jy in die vorige afdelings kan sien, gebruik beide Chrome en Firefox **SQLite**-databasisse om die data te stoor. Dit is moontlik om **verwyderde inskrywings te herstel deur die tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **of** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **te gebruik**.

## **Internet Explorer 11**

Internet Explorer 11 bestuur sy data en metadata oor verskeie liggings, wat help om gestoorde inligting en die ooreenstemmende besonderhede daarvan te skei vir maklike toegang en bestuur.

### Metadata-berging

Metadata vir Internet Explorer word gestoor in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (waar VX V01, V16 of V24 is). Die bygaande `V01.log`-lêer kan verskille in wysigingstye met `WebcacheVX.data` toon, wat aandui dat herstel met `esentutl /r V01 /d` nodig is. Hierdie metadata, wat in 'n ESE-databasis gehuisves word, kan onderskeidelik met tools soos photorec en [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) herwin en geïnspekteer word. Binne die **Containers**-tabel kan 'n mens die spesifieke tabelle of houers onderskei waar elke datasegment gestoor word, insluitend cache-besonderhede vir ander Microsoft-tools soos Skype.

### Cache-inspeksie

Die [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html)-tool laat cache-inspeksie toe en vereis die ligging van die vouer waarin die cache-data onttrek is. Metadata vir cache sluit die lêernaam, gids, toegangsaan­tal, URL-oorsprong en tydstempels in wat cache-skepping, toegang, wysiging en vervaltye aandui.

### Cookie-bestuur

Cookies kan met [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) ondersoek word, met metadata wat name, URL's, toegangsantalle en verskeie tydverwante besonderhede insluit. Volgehoue cookies word in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gestoor, terwyl sessie-cookies in die geheue bly.

### Download-besonderhede

Download-metadata is via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) toeganklik, met spesifieke houers wat data soos URL, lêertipe en download-ligging bevat. Fisiese lêers kan onder `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` gevind word.

### Blaaigeskiedenis

Om blaaigeskiedenis te hersien, kan [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gebruik word. Dit vereis die ligging van die onttrekte geskiedenislêers en konfigurasie vir Internet Explorer. Metadata hier sluit wysigings- en toegangstye, sowel as toegangsantalle, in. Geskiedenislêers is in `%userprofile%\Appdata\Local\Microsoft\Windows\History` geleë.

### Ingetikte URL's

Ingetikte URL's en die tydsberekening van hul gebruik word binne die register onder `NTUSER.DAT` by `Software\Microsoft\InternetExplorer\TypedURLs` en `Software\Microsoft\InternetExplorer\TypedURLsTime` gestoor. Dit hou die laaste 50 URL's wat deur die gebruiker ingevoer is en hul laaste invoertye dop.

## Microsoft Edge

Microsoft Edge stoor gebruikersdata in `%userprofile%\Appdata\Local\Packages`. Die paaie vir verskeie datatipes is:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-data word by `/Users/$User/Library/Safari` gestoor. Belangrike lêers sluit in:<sup>[[3]](#references)</sup>

- **History.db**: Bevat `history_visits`- en `history_items`-tabelle met URL's en besoektydstempels. Gebruik `sqlite3` om navrae uit te voer.
- **Downloads.plist**: Inligting oor afgelaaide lêers.
- **Bookmarks.plist**: Stoor geboekmerkte URL's.
- **TopSites.plist**: Mees gereeld besoekte werwe.
- **Extensions.plist**: Lys van Safari-blaaieruitbreidings. Gebruik `plutil` of `pluginkit` om dit te herwin.
- **UserNotificationPermissions.plist**: Domeine wat toegelaat word om push-kennisgewings te stuur. Gebruik `plutil` om dit te parse.
- **LastSession.plist**: Oortjies uit die vorige sessie. Gebruik `plutil` om dit te parse.
- **Browser’s built-in anti-phishing**: Kontroleer dit met `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. 'n Antwoord van 1 dui aan dat die funksie aktief is.<sup>[[2]](#references)</sup>

## Opera

Opera se data is in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` geleë en gebruik Chrome se formaat vir geskiedenis en downloads.

- **Browser’s built-in anti-phishing**: Verifieer dit deur met `grep` te kontroleer of `fraud_protection_enabled` in die Preferences-lêer op `true` gestel is.<sup>[[2]](#references)</sup>

Hierdie paaie en opdragte is noodsaaklik om toegang tot die blaaidata wat deur verskillende webblaaiers gestoor word te verkry en dit te verstaan.

## References

- [1] [Web Browsers Forensics: 'n Gids vir die uitvoer van Web Browsers Forensic Analysis](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Deel 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting and Analysis deur Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
