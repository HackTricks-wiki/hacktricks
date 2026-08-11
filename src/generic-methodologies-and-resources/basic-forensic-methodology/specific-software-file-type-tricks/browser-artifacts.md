# Blaaierartefakte

{{#include ../../../banners/hacktricks-training.md}}

## Blaaierartefakte <a href="#id-3def" id="id-3def"></a>

Blaaierartefakte sluit verskeie tipes data in wat deur webblaaiers gestoor word, soos navigasiegeskiedenis, boekmerke en kasdata. Hierdie artefakte word in spesifieke vouers binne die bedryfstelsel gehou. Die ligging en naam verskil tussen blaaiers, maar hulle stoor gewoonlik soortgelyke datatipes.

Hier is 'n opsomming van die algemeenste blaaierartefakte:

- **Navigasiegeskiedenis**: Hou rekord van gebruikerbesoeke aan webwerwe, wat nuttig is om besoeke aan kwaadwillige webwerwe te identifiseer.
- **Outovoltooiingsdata**: Voorstelle gebaseer op gereelde soektogte, wat insigte bied wanneer dit saam met navigasiegeskiedenis gebruik word.
- **Boekmerke**: Webwerwe wat deur die gebruiker gestoor is vir vinnige toegang.
- **Uitbreidings en byvoegings**: Blaaieruitbreidings of byvoegings wat deur die gebruiker geïnstalleer is.
- **Cache**: Stoor webinhoud (bv. beelde en JavaScript-lêers) om webwerflaaitye te verbeter, en is waardevol vir forensiese ontleding.
- **Aanmeldings**: Gestoorde aanmeldbewyse.
- **Favicons**: Ikone wat met webwerwe geassosieer word en in oortjies en boekmerke verskyn, en wat nuttig is vir bykomende inligting oor gebruikerbesoeke.
- **Blaaiersessies**: Data wat met oop blaaiersessies verband hou.
- **Aflaaie**: Rekords van lêers wat deur die blaaier afgelaai is.
- **Vormdata**: Inligting wat in webvorms ingevoer is en vir toekomstige outovoltooiingsvoorstelle gestoor word.
- **Kleinkiekies**: Voorskoubeelde van webwerwe.
- **Custom Dictionary.txt**: Woorde wat deur die gebruiker by die blaaier se woordeboek gevoeg is.

## Firefox

Firefox organiseer gebruikerdata binne profiele wat in spesifieke liggings gestoor word, afhangend van die bedryfstelsel:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

'n `profiles.ini`-lêer binne hierdie gidse lys die gebruikerprofiele. Elke profiel se data word gestoor in 'n vouer met die naam wat in die `Path`-veranderlike binne `profiles.ini` gespesifiseer word, en wat in dieselfde gids as `profiles.ini` self geleë is. As 'n profiel se vouer ontbreek, is dit moontlik dat dit verwyder is.

Binne elke profielvouer kan jy verskeie belangrike lêers vind:<sup>[[1]](#references)</sup>

- **places.sqlite**: Stoor geskiedenis, boekmerke en aflaaie. Gereedskap soos [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) op Windows kan toegang tot die geskiedenিসdata verkry.
- Gebruik spesifieke SQL-navrae om geskiedenis- en aflaai-inligting te onttrek.
- **bookmarkbackups**: Bevat rugsteun van boekmerke.
- **formhistory.sqlite**: Stoor webvormdata.
- **handlers.json**: Bestuur protokolhanteerders.
- **persdict.dat**: Pasgemaakte woordeboekwoorde.
- **addons.json** en **extensions.sqlite**: Inligting oor geïnstalleerde byvoegings en uitbreidings.
- **cookies.sqlite**: Koekiestoorplek, met [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) beskikbaar vir inspeksie op Windows.
- **cache2/entries** of **startupCache**: Kasdata, toeganklik deur gereedskap soos [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Stoor favicons.
- **prefs.js**: Gebruikerinstellings en -voorkeure.
- **downloads.sqlite**: Ouer aflaaidatabasis, wat nou in places.sqlite geïntegreer is.
- **thumbnails**: Webwerkkleinkiekies.
- **logins.json**: Geënkripteerde aanmeldinligting.
- **key4.db** of **key3.db**: Stoor enkripsiesleutels om sensitiewe inligting te beveilig.

Daarbenewens kan die blaaier se anti-phishing-instellings nagegaan word deur na `browser.safebrowsing`-inskrywings in `prefs.js` te soek. Dit dui aan of veilige-blaaifunksies geaktiveer of gedeaktiveer is.<sup>[[2]](#references)</sup>

Om die hoofwagwoord te probeer dekripteer, kan jy [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) gebruik\
Met die volgende script en oproep kan jy 'n wagwoordlêer spesifiseer om brute force uit te voer:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Browserartefakte - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome stoor gebruikersprofiele op spesifieke liggings gebaseer op die bedryfstelsel:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Binne hierdie gidse kan die meeste gebruikersdata in die **Default/**- of **ChromeDefaultData/**-vouers gevind word. Die volgende lêers bevat belangrike data:<sup>[[1]](#references)</sup>

- **History**: Bevat URLs, downloads en soeksleutelwoorde. Op Windows kan [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) gebruik word om die geskiedenis te lees. Die kolom "Transition Type" het verskeie betekenisse, insluitend gebruikersklikke op links, ingetikte URLs, vormindienings en bladsyherlaaie.
- **Cookies**: Stoor cookies. Vir inspeksie is [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) beskikbaar.
- **Cache**: Bevat gecachete data. Om dit te inspekteer, kan Windows-gebruikers [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) gebruik.

Electron-gebaseerde desktop-apps (bv. Discord) gebruik ook Chromium Simple Cache en laat uitgebreide artefakte op die skyf agter. Sien:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Gebruiker se bookmarks.
- **Web Data**: Bevat vormgeskiedenis.
- **Favicons**: Stoor webwerf-favicons.
- **Login Data**: Bevat login credentials soos gebruikersname en wagwoorde.
- **Current Session**/**Current Tabs**: Data oor die huidige blaaisessie en oop tabs.
- **Last Session**/**Last Tabs**: Inligting oor die webwerwe wat aktief was tydens die laaste sessie voordat Chrome gesluit is.
- **Extensions**: Gidse vir browser extensions en addons.
- **Thumbnails**: Stoor webwerf-thumbnails.
- **Preferences**: ’n Lêer ryk aan inligting, insluitend instellings vir plugins, extensions, pop-ups, notifications en meer.
- **Browser’s built-in anti-phishing**: Om te kontroleer of anti-phishing- en malware-beskerming geaktiveer is, voer `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` uit. Soek na `{"enabled: true,"}` in die uitvoer.<sup>[[2]](#references)</sup>

## **SQLite DB-dataherwinning**

Soos in die vorige afdelings waargeneem kan word, gebruik Chrome en Firefox albei **SQLite**-databasisse om die data te stoor. Dit is moontlik om **deleted entries met die tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **of** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **te herwin**.

## **Internet Explorer 11**

Internet Explorer 11 bestuur sy data en metadata oor verskeie liggings, wat help om gestoorde inligting en die ooreenstemmende besonderhede daarvan te skei vir maklike toegang en bestuur.

### Metadataberging

Metadata vir Internet Explorer word in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` gestoor (waar VX V01, V16 of V24 is). Die meegaande `V01.log`-lêer kan verskille in wysigingstyd met `WebcacheVX.data` toon, wat aandui dat herstel met `esentutl /r V01 /d` nodig is. Hierdie metadata, wat in ’n ESE-databasis gehuisves word, kan onderskeidelik met tools soos photorec en [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) herwin en geïnspekteer word. Binne die **Containers**-tabel kan ’n mens die spesifieke tabelle of containers onderskei waar elke datasegment gestoor word, insluitend cache-besonderhede vir ander Microsoft-tools soos Skype.

### Cache-inspeksie

Die [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html)-tool laat cache-inspeksie toe en vereis die ligging van die vouer waarheen die cache-data onttrek is. Metadata vir cache sluit die lêernaam, gids, toegangstelling, URL-oorsprong en tydstempels in wat cache-skepping-, toegang-, wysigings- en vervaltye aandui.

### Cookies-bestuur

Cookies kan met [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) ondersoek word, met metadata wat name, URLs, toegangstellings en verskeie tydverwante besonderhede insluit. Permanente cookies word in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gestoor, terwyl sessie-cookies in die geheue bly.

### Download-besonderhede

Download-metadata is via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) toeganklik, met spesifieke containers wat data soos URL, lêertipe en download-ligging bevat. Fisiese lêers kan onder `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` gevind word.

### Blaaigeskiedenis

Om die blaaigeskiedenis te hersien, kan [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gebruik word. Dit vereis die ligging van onttrekte geskiedenislêers en konfigurasie vir Internet Explorer. Metadata hier sluit wysigings- en toegangstye, sowel as toegangstellings, in. Geskiedenislêers is in `%userprofile%\Appdata\Local\Microsoft\Windows\History` geleë.

### Ingetikte URLs

Ingetikte URLs en hul gebruikstye word in die register onder `NTUSER.DAT` by `Software\Microsoft\InternetExplorer\TypedURLs` en `Software\Microsoft\InternetExplorer\TypedURLsTime` gestoor. Dit hou die laaste 50 URLs wat deur die gebruiker ingevoer is en hul laaste invoertye na.

## Microsoft Edge

Microsoft Edge stoor gebruikersdata in `%userprofile%\Appdata\Local\Packages`. Die paaie vir verskeie datatipes is:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-data word by `/Users/$User/Library/Safari` gestoor. Belangrike lêers sluit in:<sup>[[3]](#references)</sup>

- **History.db**: Bevat `history_visits`- en `history_items`-tabelle met URLs en besoektydstempels. Gebruik `sqlite3` om navrae uit te voer.
- **Downloads.plist**: Inligting oor afgelaaide lêers.
- **Bookmarks.plist**: Stoor geboekmerkte URLs.
- **TopSites.plist**: Webwerwe wat die meeste besoek word.
- **Extensions.plist**: Lys van Safari-browserextensions. Gebruik `plutil` of `pluginkit` om dit te herwin.
- **UserNotificationPermissions.plist**: Domeine wat toegelaat word om push-notifications te stuur. Gebruik `plutil` om dit te parse.
- **LastSession.plist**: Tabs van die laaste sessie. Gebruik `plutil` om dit te parse.
- **Browser’s built-in anti-phishing**: Kontroleer dit met `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. ’n Respons van 1 dui aan dat die funksie aktief is.<sup>[[2]](#references)</sup>

## Opera

Opera se data is in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` geleë en gebruik Chrome se formaat vir geskiedenis en downloads.

- **Browser’s built-in anti-phishing**: Verifieer dit deur met `grep` te kontroleer of `fraud_protection_enabled` in die Preferences-lêer op `true` gestel is.<sup>[[2]](#references)</sup>

Hierdie paaie en commands is noodsaaklik om toegang te verkry tot en begrip te ontwikkel van die blaaidata wat deur verskillende webblaaiers gestoor word.

## References

- [1] [Webblaaiers-forensika: ’n Gids tot die uitvoer van forensiese ontleding van webblaaiers](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Deel 3: Stelselmanipulasie](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting and Analysis deur Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
