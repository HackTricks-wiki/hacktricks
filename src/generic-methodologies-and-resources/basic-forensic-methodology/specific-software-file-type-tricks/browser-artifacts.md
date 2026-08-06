# Blaaier-artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Blaaier-artefakte <a href="#id-3def" id="id-3def"></a>

Blaaier-artefakte sluit verskeie tipes data in wat deur webblaaiers gestoor word, soos navigasiegeskiedenis, boekmerke en kasdata. Hierdie artefakte word in spesifieke vouers binne die bedryfstelsel gehou. Die ligging en naam verskil tussen blaaiers, maar hulle stoor oor die algemeen soortgelyke datatipes.

Hier is 'n opsomming van die algemeenste blaaier-artefakte:

- **Navigasiegeskiedenis**: Hou rekord van gebruikers se webwerfbesoeke en is nuttig om besoeke aan malicious webwerwe te identifiseer.
- **Outovoltooi-data**: Voorstelle gebaseer op gereelde soektogte, wat insigte bied wanneer dit saam met navigasiegeskiedenis gebruik word.
- **Boekmerke**: Werwe wat deur die gebruiker gestoor is vir vinnige toegang.
- **Extensions en Add-ons**: Browser extensions of add-ons wat deur die gebruiker geïnstalleer is.
- **Kas**: Stoor webinhoud (bv. beelde en JavaScript-lêers) om webwerwe vinniger te laai en is waardevol vir forensiese ontleding.
- **Aanmeldings**: Gestoorde aanmeldbewyse.
- **Favicons**: Ikone wat met webwerwe geassosieer word en in oortjies en boekmerke verskyn; nuttig vir bykomende inligting oor gebruikers se besoeke.
- **Blaaiersessies**: Data wat verband hou met oop blaaier-sessies.
- **Aflaaie**: Rekords van lêers wat deur die blaaier afgelaai is.
- **Vormdata**: Inligting wat in webvorms ingevoer is en vir toekomstige outovul-voorstelle gestoor word.
- **Duimnaels**: Voorskoubeelde van webwerwe.
- **Custom Dictionary.txt**: Woorde wat deur die gebruiker by die blaaier se woordeboek gevoeg is.

## Firefox

Firefox organiseer gebruikersdata binne profiele wat in spesifieke liggings gestoor word, gebaseer op die bedryfstelsel:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

'n `profiles.ini`-lêer binne hierdie gidse lys die gebruikersprofiele. Elke profiel se data word gestoor in 'n vouer met die naam in die `Path`-veranderlike binne `profiles.ini`, wat in dieselfde gids as `profiles.ini` self geleë is. Indien 'n profiel se vouer ontbreek, is dit moontlik dat dit verwyder is.

Binne elke profielvouer kan jy verskeie belangrike lêers vind:<sup>[[1]](#references)</sup>

- **places.sqlite**: Stoor geskiedenis, boekmerke en aflaaie. Tools soos [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) op Windows kan toegang tot die geskiedenisinligting verkry.
- Gebruik spesifieke SQL queries om geskiedenis- en aflaai-inligting te onttrek.
- **bookmarkbackups**: Bevat rugsteunkopieë van boekmerke.
- **formhistory.sqlite**: Stoor webvormdata.
- **handlers.json**: Bestuur protokolhanteringsfunksies.
- **persdict.dat**: Custom Dictionary-woorde.
- **addons.json** en **extensions.sqlite**: Inligting oor geïnstalleerde add-ons en extensions.
- **cookies.sqlite**: Koekieberging, met [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) wat op Windows beskikbaar is vir inspeksie.
- **cache2/entries** of **startupCache**: Kasdata, toeganklik deur tools soos [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Stoor favicons.
- **prefs.js**: Gebruikersinstellings en -voorkeure.
- **downloads.sqlite**: Ouer aflaaidatabasis, wat nou in places.sqlite geïntegreer is.
- **thumbnails**: Webwerfduimnaels.
- **logins.json**: Geënkripteerde aanmeldinligting.
- **key4.db** of **key3.db**: Stoor enkripsiesleutels om sensitiewe inligting te beveilig.

Daarbenewens kan die blaaier se anti-phishing-instellings nagegaan word deur vir `browser.safebrowsing`-inskrywings in `prefs.js` te soek. Dit dui aan of safe browsing-funksies geaktiveer of gedeaktiveer is.<sup>[[2]](#references)</sup>

Om te probeer om die master password te dekripteer, kan jy [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) gebruik\
Met die volgende script en call kan jy 'n wagwoordlêer spesifiseer om te brute force:
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

- **History**: Bevat URL's, downloads en soeksleutelwoorde. Op Windows kan [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) gebruik word om die geskiedenis te lees. Die kolom "Transition Type" het verskeie betekenisse, insluitend gebruikersklikke op skakels, getikte URL's, vormindienings en bladsyherlaaie.
- **Cookies**: Stoor cookies. Vir inspeksie is [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) beskikbaar.
- **Cache**: Bevat gecachede data. Windows-gebruikers kan [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) gebruik om dit te inspekteer.

Electron-gebaseerde desktop-apps (byvoorbeeld Discord) gebruik ook Chromium Simple Cache en laat uitgebreide artefakte op skyf agter. Sien:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Gebruikersboekmerke.
- **Web Data**: Bevat vormgeskiedenis.
- **Favicons**: Stoor webwerf-favicons.
- **Login Data**: Bevat aanmeldingsbewyse soos gebruikersname en wagwoorde.
- **Current Session**/**Current Tabs**: Data oor die huidige blaaisessie en oop oortjies.
- **Last Session**/**Last Tabs**: Inligting oor die webwerwe wat aktief was tydens die vorige sessie voordat Chrome gesluit is.
- **Extensions**: Gidse vir blaaieruitbreidings en addons.
- **Thumbnails**: Stoor webwerf-kleinkiekies.
- **Preferences**: 'n Lêer met baie inligting, insluitend instellings vir plugins, uitbreidings, pop-ups, kennisgewings en meer.
- **Browser’s built-in anti-phishing**: Om te kyk of anti-phishing- en malware-beskerming geaktiveer is, voer `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` uit. Soek vir `{"enabled: true,"}` in die uitvoer.<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

Soos jy in die vorige afdelings kan sien, gebruik beide Chrome en Firefox **SQLite**-databasisse om die data te stoor. Dit is moontlik om **deleted entries met die tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **of** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **te recover**.

## **Internet Explorer 11**

Internet Explorer 11 bestuur sy data en metadata op verskeie liggings, wat help om gestoorde inligting en die ooreenstemmende besonderhede daarvan te skei vir maklike toegang en bestuur.

### Metadata Storage

Metadata vir Internet Explorer word gestoor in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (waar VX V01, V16 of V24 is). Die gepaardgaande `V01.log`-lêer kan verskille in wysigingstyd met `WebcacheVX.data` toon, wat aandui dat herstel met `esentutl /r V01 /d` nodig is. Hierdie metadata, wat in 'n ESE-databasis gehuisves word, kan onderskeidelik met tools soos photorec en [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) recovered en geïnspekteer word. Binne die **Containers**-tabel kan 'n mens die spesifieke tabelle of containers identifiseer waarin elke datasegment gestoor word, insluitend cache-besonderhede vir ander Microsoft-tools soos Skype.

### Cache Inspection

Die [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html)-tool laat cache-inspeksie toe en vereis die ligging van die vouer waarheen die cache-data geëkstraheer is. Metadata vir cache sluit die lêernaam, gids, aantal toegange, URL-oorsprong en tydstempels in wat die cache se skepping, toegang, wysiging en vervaltye aandui.

### Cookies Management

Cookies kan met [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) ondersoek word, met metadata wat name, URL's, aantal toegange en verskeie tydverwante besonderhede insluit. Persistente cookies word in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gestoor, terwyl sessiecookies in die geheue bly.

### Download Details

Download-metadata is via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) toeganklik, met spesifieke containers wat data soos URL, lêertipe en download-ligging bevat. Fisiese lêers kan onder `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` gevind word.

### Browsing History

Om blaai-geskiedenis te hersien, kan [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gebruik word. Dit vereis die ligging van die geëkstraheerde geskiedenislêers en konfigurasie vir Internet Explorer. Metadata hier sluit wysigings- en toegangstye, sowel as toegangstellings, in. Geskiedenislêers is in `%userprofile%\Appdata\Local\Microsoft\Windows\History` geleë.

### Typed URLs

Getikte URL's en die tye waarop hulle gebruik is, word in die registry onder `NTUSER.DAT` by `Software\Microsoft\InternetExplorer\TypedURLs` en `Software\Microsoft\InternetExplorer\TypedURLsTime` gestoor. Dit hou die laaste 50 URL's wat deur die gebruiker ingevoer is en die tye waarop hulle laas ingevoer is, by.

## Microsoft Edge

Microsoft Edge stoor gebruikersdata in `%userprofile%\Appdata\Local\Packages`. Die paths vir verskeie datatipes is:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-data word by `/Users/$User/Library/Safari` gestoor. Belangrike lêers sluit in:<sup>[[3]](#references)</sup>

- **History.db**: Bevat `history_visits`- en `history_items`-tabelle met URL's en besoektydstempels. Gebruik `sqlite3` om navrae uit te voer.
- **Downloads.plist**: Inligting oor afgelaaide lêers.
- **Bookmarks.plist**: Stoor boekmerk-URL's.
- **TopSites.plist**: Webwerwe wat die meeste besoek word.
- **Extensions.plist**: Lys van Safari-blaaieruitbreidings. Gebruik `plutil` of `pluginkit` om dit te retrieve.
- **UserNotificationPermissions.plist**: Domeine wat toegelaat word om push-kennisgewings te stuur. Gebruik `plutil` om dit te parse.
- **LastSession.plist**: Oortjies van die vorige sessie. Gebruik `plutil` om dit te parse.
- **Browser’s built-in anti-phishing**: Kontroleer met `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. 'n Antwoord van 1 dui aan dat die funksie aktief is.<sup>[[2]](#references)</sup>

## Opera

Opera se data is in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` geleë en gebruik Chrome se formaat vir geskiedenis en downloads.

- **Browser’s built-in anti-phishing**: Verifieer dit deur met `grep` te kontroleer of `fraud_protection_enabled` in die Preferences-lêer op `true` gestel is.<sup>[[2]](#references)</sup>

Hierdie paths en commands is belangrik vir toegang tot en begrip van die blaaidata wat deur verskillende webblaaiers gestoor word.

## References

- [1] [Web Browsers Forensics: A Guide On Doing Web Browsers Forensic Analysis](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting and Analysis by Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)

{{#include ../../../banners/hacktricks-training.md}}
