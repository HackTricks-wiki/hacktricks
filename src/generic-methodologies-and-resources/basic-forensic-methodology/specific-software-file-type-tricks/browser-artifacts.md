# Blaaier-artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Blaaiers-artefakte <a href="#id-3def" id="id-3def"></a>

Blaaier-artefakte sluit verskeie tipes data in wat deur webblaaiers gestoor word, soos navigasiegeskiedenis, bladmerke en kas-data. Hierdie artefakte word in spesifieke gidse binne die bedryfstelsel gehou, met verskille in ligging en naam tussen blaaiers, maar stoor oor die algemeen soortgelyke datatipes.

Hier is 'n opsomming van die mees algemene blaaier-artefakte:

- **Navigasiegeskiedenis**: Volg gebruikersbesoeke aan webwerwe, nuttig om besoeke aan kwaadwillige werwe te identifiseer.
- **Outomatiese voltooiingsdata**: Voorstelle gebaseer op gereelde soektogte, bied insigte wanneer gekombineer met navigasiegeskiedenis.
- **Bladmerke**: Werwe deur die gebruiker gestoor vir vinnige toegang.
- **Uitbreidings en byvoegsels**: Browserverlengings of byvoegsels wat deur die gebruiker geïnstalleer is.
- **Kas**: Stoor webinhoud (bv. beelde, JavaScript-lêers) om webwerf-laaisnelhede te verbeter; waardevol vir forensiese ontleding.
- **Aanmeldings**: Gestoor aanmeldbewyse.
- **Favicons**: Ikone geassosieer met webwerwe, vertoon in oortjies en bladmerke, nuttig vir addisionele inligting oor gebruikersbesoeke.
- **Blaaier-sessies**: Data verwant aan oop blaaier-sessies.
- **Aflaaie**: Rekords van lêers wat deur die blaaier afgelaai is.
- **Vormdata**: Inligting wat in webvorms ingevoer is, gestoor vir toekomstige autofill-voorstelle.
- **Voorbeeldminiature**: Voorskoubeelde van webwerwe.
- **Custom Dictionary.txt**: Woorde deur die gebruiker by die blaaier se woordeboek gevoeg.

## Firefox

Firefox organiseer gebruikersdata binne profiele, wat in spesifieke liggings gebaseer op die bedryfstelsel gestoor word:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

'n `profiles.ini`-lêer binne hierdie gidse lys die gebruikersprofiele. Elke profiel se data word in 'n gids gestoor wat in die `Path`-variabele binne `profiles.ini` genoem word, geleë in dieselfde gids as `profiles.ini` self. Indien 'n profielgids ontbreek, kan dit verwyder gewees het.

Binne elke profielgids kan jy verskeie belangrike lêers vind:

- **places.sqlite**: Stoor geskiedenis, bladmerke en aflaaie. Gereedskap soos [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) op Windows kan toegang gee tot die geskiedenisdata.
- Gebruik spesifieke SQL-vrae om geskiedenis- en aflaai-inligting te onttrek.
- **bookmarkbackups**: Bevat rugsteunlêers van bladmerke.
- **formhistory.sqlite**: Stoor webvormdata.
- **handlers.json**: Beheer protokolhandelaars.
- **persdict.dat**: Aangepaste woordeboekwoorde.
- **addons.json** en **extensions.sqlite**: Inligting oor geïnstalleerde byvoegsels en uitbreidings.
- **cookies.sqlite**: Koekiesberging, met [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) beskikbaar vir inspeksie op Windows.
- **cache2/entries** of **startupCache**: Kasdata, toeganklik deur gereedskap soos [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Stoor favicons.
- **prefs.js**: Gebruikersinstellings en voorkeure.
- **downloads.sqlite**: Ouer aflaaibasis, nou geïntegreer in places.sqlite.
- **thumbnails**: Webwerf-voorskoue.
- **logins.json**: Gekodeerde aanmeldinligting.
- **key4.db** of **key3.db**: Stoor enkripsiesleutels wat sensitiewe inligting beveilig.

Daarbenewens kan die blaaier se anti-phishing-instellings nagegaan word deur te soek na `browser.safebrowsing`-inskrywings in `prefs.js`, wat aandui of safe browsing-funksies geaktiveer of gedeaktiveer is.

Om te probeer om die meesterwagwoord te ontsleutel, kan jy gebruik [https://github.com/unode/firefox_decrypt]\
Met die volgende skrip en oproep kan jy 'n wagwoordlêer spesifiseer om deur brute force te probeer:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (692).png>)

## Google Chrome

Google Chrome stoor gebruikerprofiele in spesifieke plekke afhangend van die bedryfstelsel:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Binne hierdie gidse word meeste gebruikersdata in die **Default/** of **ChromeDefaultData/** -vouers gevind. Die volgende lêers bevat betekenisvolle data:

- **History**: Bevat URLs, downloads en soekwoorde. Op Windows kan [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) gebruik word om die history te lees. Die "Transition Type" kolom het verskeie betekenisse, insluitende gebruikerklik op skakels, ingetypte URLs, vorminskrywings en bladsy-herlaaiings.
- **Cookies**: Stoor cookies. Vir inspeksie is [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) beskikbaar.
- **Cache**: Bevat gecachte data. Om te inspekteer kan Windows-gebruikers [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) gebruik.

Electron-based desktop apps (bv. Discord) gebruik ook Chromium Simple Cache en laat baie on-disk artefakte agter. Sien:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Gebruiker se bookmarks.
- **Web Data**: Bevat vormgeskiedenis.
- **Favicons**: Stoor webwerf-favicons.
- **Login Data**: Sluit aanmeldinligting in soos gebruikersname en wagwoorde.
- **Current Session**/**Current Tabs**: Data oor die huidige blaai-sessie en oop tabbladsye.
- **Last Session**/**Last Tabs**: Inligting oor die webwerwe wat aktief was tydens die laaste sessie voordat Chrome gesluit is.
- **Extensions**: Gidse vir browser-uitbreidings en addons.
- **Thumbnails**: Stoor webwerf-miniatuurbeelde.
- **Preferences**: 'n Lêer ryk aan inligting, insluitende instellings vir plugins, uitbreidings, pop-ups, kennisgewings en meer.
- **Browser’s built-in anti-phishing**: Om te kontroleer of anti-phishing en malware-beskerming aangeskakel is, voer uit `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Kyk vir `{"enabled: true,"}` in die uitset.

## **SQLite DB Data Recovery**

Soos jy in die vorige afdelings kan sien, gebruik beide Chrome en Firefox **SQLite** databasisse om data te stoor. Dit is moontlik om **verwyderde inskrywings te herstel met die hulpmiddel** [**sqlparse**](https://github.com/padfoot999/sqlparse) **of** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 bestuur sy data en metadata oor verskeie plekke, wat help om gestoorde inligting en die ooreenstemmende besonderhede te skei vir maklike toegang en bestuur.

### Metadata Storage

Metadata vir Internet Explorer word gestoor in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (met VX wat V01, V16 of V24 kan wees). Saam met dit kan die `V01.log` lêer wys dat wysigingstye nie ooreenstem met `WebcacheVX.data` nie, wat dui op 'n behoefte om te herstel met `esentutl /r V01 /d`. Hierdie metadata, gehuisves in 'n ESE-databasis, kan herstel en ondersoek word met gereedskap soos photorec en [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), onderskeidelik. Binne die **Containers** tabel kan mens die spesifieke tabelle of houers onderskei waar elke datasegment gestoor is, insluitende cache-besonderhede vir ander Microsoft-instrumente soos Skype.

### Cache Inspection

Die [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) hulpmiddel laat cache-inspeksie toe en vereis die ligging van die uitgehaalde cache-data gids. Metadata vir die cache sluit lêernaam, gids, toegangsteller, URL-bron en tydstempel in wat aandui wanneer die cache geskep, geraak, gewysig en verval het.

### Cookies Management

Cookies kan ondersoek word met [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), met metadata wat name, URLs, toegangstellings en verskeie tydverwante besonderhede insluit. Persistent cookies word gestoor in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, terwyl sessie-cookies in geheue bly.

### Download Details

Downloads metadata is toeganklik via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), met spesifieke containers wat data soos URL, lêertipe en aflaailigging bevat. Fisiese lêers kan gevind word onder `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Om blaai-geskiedenis na te gaan, kan [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gebruik word; dit vereis die ligging van uitgehaalde history-lêers en konfigurasie vir Internet Explorer. Metadata hier sluit wysiging- en toegangstye, sowel as toegangstellings, in. History-lêers is geleë in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Ingetypte URLs en hul gebruikstye word in die register gehou onder `NTUSER.DAT` by `Software\Microsoft\InternetExplorer\TypedURLs` en `Software\Microsoft\InternetExplorer\TypedURLsTime`, wat die laaste 50 URLs wat die gebruiker ingevoer het en hul laaste invoertye dop.

## Microsoft Edge

Microsoft Edge stoor gebruikerdata in `%userprofile%\Appdata\Local\Packages`. Die paaie vir verskeie datatipes is:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-data word gestoor by `/Users/$User/Library/Safari`. Sleutellêers sluit in:

- **History.db**: Bevat `history_visits` en `history_items` tabelle met URLs en besoektye. Gebruik `sqlite3` om navraag te doen.
- **Downloads.plist**: Inligting oor afgelaaide lêers.
- **Bookmarks.plist**: Stoor gebladerde bookmarks.
- **TopSites.plist**: Mees gereeld besoekte webwerwe.
- **Extensions.plist**: Lys van Safari-browseruitbreidings. Gebruik `plutil` of `pluginkit` om te herwin.
- **UserNotificationPermissions.plist**: Domeine wat toegelaat is om kennisgewings te stuur. Gebruik `plutil` om te parse.
- **LastSession.plist**: Tabbladsye van die laaste sessie. Gebruik `plutil` om te parse.
- **Browser’s built-in anti-phishing**: Kontroleer met `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. 'n Antwoord van 1 dui daarop dat die funksie aktief is.

## Opera

Opera se data is geleë in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` en deel Chrome se formaat vir history en downloads.

- **Browser’s built-in anti-phishing**: Verifieer deur te kontroleer of `fraud_protection_enabled` in die Preferences-lêer op `true` gestel is met `grep`.

Hierdie paaie en opdragte is noodsaaklik om toegang te kry tot en begrip te hê van die blaai-data wat deur verskillende webblaaiers gestoor word.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**


{{#include ../../../banners/hacktricks-training.md}}
