# Bladsy Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Bladsy Artefakte <a href="#id-3def" id="id-3def"></a>

Bladsy artefakte sluit verskeie tipes data in wat deur webblaaiers gestoor word, soos navigasiegeskiedenis, boekmerke en kasdata. Hierdie artefakte word in spesifieke vouers binne die bedryfstelsel gehou, wat verskil in ligging en naam oor blaaiers, maar oor die algemeen soortgelyke datatipes stoor.

Hier is 'n opsomming van die mees algemene bladsy artefakte:

- **Navigasiegeskiedenis**: Hou gebruikersbesoeke aan webwerwe dop, nuttig om besoeke aan kwaadwillige webwerwe te identifiseer.
- **Outomatiese Voltooiing Data**: Voorstelle gebaseer op gereelde soektogte, wat insigte bied wanneer dit gekombineer word met navigasiegeskiedenis.
- **Boekmerke**: Webwerwe wat deur die gebruiker gestoor is vir vinnige toegang.
- **Uitbreidings en Byvoegings**: Blaaieruitbreidings of byvoegings wat deur die gebruiker geïnstalleer is.
- **Kas**: Stoor webinhoud (bv. beelde, JavaScript-lêers) om webwerf laaitye te verbeter, waardevol vir forensiese analise.
- **Inloggings**: Gestoor inlogbesonderhede.
- **Favicons**: Ikone wat met webwerwe geassosieer word, wat in oortjies en boekmerke verskyn, nuttig vir addisionele inligting oor gebruikersbesoeke.
- **Blaaier Sessies**: Data verwant aan oop blaaier sessies.
- **Aflaaie**: Rekords van lêers wat deur die blaaier afgelaai is.
- **Vormdata**: Inligting ingevoer in webvorms, gestoor vir toekomstige outomatiese voltooiingsvoorstelle.
- **Miniatuurbeelde**: Voorvertoning beelde van webwerwe.
- **Custom Dictionary.txt**: Woorde wat deur die gebruiker aan die blaaier se woordeskat bygevoeg is.

## Firefox

Firefox organiseer gebruikersdata binne profiele, gestoor in spesifieke plekke gebaseer op die bedryfstelsel:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

'n `profiles.ini` lêer binne hierdie gidse lys die gebruikersprofiele. Elke profiel se data word in 'n vouer gestoor wat in die `Path` veranderlike binne `profiles.ini` genoem word, geleë in dieselfde gids as `profiles.ini` self. As 'n profiel se vouer ontbreek, mag dit verwyder wees.

Binne elke profiel vouer kan jy verskeie belangrike lêers vind:

- **places.sqlite**: Stoor geskiedenis, boekmerke en aflaaie. Gereedskap soos [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) op Windows kan toegang tot die geskiedenisdata verkry.
- Gebruik spesifieke SQL navrae om geskiedenis en aflaaie inligting te onttrek.
- **bookmarkbackups**: Bevat rugsteun van boekmerke.
- **formhistory.sqlite**: Stoor webvormdata.
- **handlers.json**: Bestuur protokolhanterings.
- **persdict.dat**: Aangepaste woordeskat woorde.
- **addons.json** en **extensions.sqlite**: Inligting oor geïnstalleerde byvoegings en uitbreidings.
- **cookies.sqlite**: Koekie stoor, met [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) beskikbaar vir inspeksie op Windows.
- **cache2/entries** of **startupCache**: Kasdata, toeganklik deur gereedskap soos [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Stoor favicons.
- **prefs.js**: Gebruikersinstellings en voorkeure.
- **downloads.sqlite**: Ouers aflaaie databasis, nou geïntegreer in places.sqlite.
- **thumbnails**: Webwerf miniatuurbeelde.
- **logins.json**: Geënkripteerde inligting oor aanmeldings.
- **key4.db** of **key3.db**: Stoor enkripsiesleutels om sensitiewe inligting te beveilig.

Boonop kan die blaaier se anti-phishing instellings nagegaan word deur te soek na `browser.safebrowsing` inskrywings in `prefs.js`, wat aandui of veilige blaai funksies geaktiveer of gedeaktiveer is.

Om te probeer om die meesterwagwoord te ontsleutel, kan jy [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Met die volgende skrip en oproep kan jy 'n wagwoord lêer spesifiseer om te brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (417).png>)

## Google Chrome

Google Chrome stoor gebruikersprofiele in spesifieke plekke gebaseer op die bedryfstelsel:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Binne hierdie gidse kan die meeste gebruikersdata in die **Default/** of **ChromeDefaultData/** vouers gevind word. Die volgende lêers hou belangrike data:

- **History**: Bevat URL's, aflaaie, en soekwoorde. Op Windows kan [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) gebruik word om die geskiedenis te lees. Die "Transition Type" kolom het verskeie betekenisse, insluitend gebruikersklicks op skakels, getypte URL's, vormindienings, en bladsyherlaai.
- **Cookies**: Stoor koekies. Vir inspeksie is [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) beskikbaar.
- **Cache**: Hou gekapte data. Om te inspekteer, kan Windows-gebruikers [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) gebruik.
- **Bookmarks**: Gebruikers se boekmerke.
- **Web Data**: Bevat vormgeskiedenis.
- **Favicons**: Stoor webwerf favicons.
- **Login Data**: Sluit aanmeldbesonderhede soos gebruikersname en wagwoorde in.
- **Current Session**/**Current Tabs**: Data oor die huidige blaai-sessie en oop oortjies.
- **Last Session**/**Last Tabs**: Inligting oor die webwerwe wat aktief was tydens die laaste sessie voordat Chrome gesluit is.
- **Extensions**: Gidse vir blaaiers se uitbreidings en addons.
- **Thumbnails**: Stoor webwerf duimnaels.
- **Preferences**: 'n Lêer ryk aan inligting, insluitend instellings vir plugins, uitbreidings, pop-ups, kennisgewings, en meer.
- **Browser’s built-in anti-phishing**: Om te kontroleer of anti-phishing en malware beskerming geaktiveer is, voer `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` uit. Soek na `{"enabled: true,"}` in die uitvoer.

## **SQLite DB Data Recovery**

Soos jy in die vorige afdelings kan sien, gebruik beide Chrome en Firefox **SQLite** databasisse om die data te stoor. Dit is moontlik om **verwyderde inskrywings te herstel met die hulpmiddel** [**sqlparse**](https://github.com/padfoot999/sqlparse) **of** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 bestuur sy data en metadata oor verskeie plekke, wat help om gestoor inligting en sy ooreenstemmende besonderhede te skei vir maklike toegang en bestuur.

### Metadata Storage

Metadata vir Internet Explorer word gestoor in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (met VX wat V01, V16, of V24 is). Saam hiermee kan die `V01.log` lêer wys datums van wysigings wat nie ooreenstem met `WebcacheVX.data` nie, wat 'n behoefte aan herstel aandui met `esentutl /r V01 /d`. Hierdie metadata, wat in 'n ESE-databasis gehuisves word, kan herstel en ondersoek word met hulpmiddels soos photorec en [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), onderskeidelik. Binne die **Containers** tabel kan 'n mens die spesifieke tabelle of houers waar elke datasegment gestoor is, onderskei, insluitend cache besonderhede vir ander Microsoft gereedskap soos Skype.

### Cache Inspection

Die [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) hulpmiddel laat vir cache-inspeksie toe, wat die cache data ekstraksie vouer plek vereis. Metadata vir cache sluit lêernaam, gids, toegangstelling, URL oorsprong, en tydstempels in wat die cache skepping, toegang, wysiging, en vervaldatums aandui.

### Cookies Management

Koekies kan ondersoek word met [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), met metadata wat name, URL's, toegangstelling, en verskeie tydverwante besonderhede insluit. Volhoubare koekies word gestoor in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, met sessie koekies wat in geheue woon.

### Download Details

Aflaai metadata is toeganklik via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), met spesifieke houers wat data soos URL, lêertipe, en aflaai plek hou. Fisiese lêers kan gevind word onder `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Om blaai geskiedenis te hersien, kan [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gebruik word, wat die plek van ekstrakte geskiedenis lêers en konfigurasie vir Internet Explorer vereis. Metadata hier sluit wysigings- en toegangstye in, saam met toegangstelling. Geskiedenis lêers is geleë in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Getypte URL's en hul gebruikstye word gestoor in die register onder `NTUSER.DAT` by `Software\Microsoft\InternetExplorer\TypedURLs` en `Software\Microsoft\InternetExplorer\TypedURLsTime`, wat die laaste 50 URL's wat deur die gebruiker ingevoer is en hul laaste invoertye volg.

## Microsoft Edge

Microsoft Edge stoor gebruikersdata in `%userprofile%\Appdata\Local\Packages`. Die paaie vir verskeie datatipes is:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari data word gestoor by `/Users/$User/Library/Safari`. Sleutellêers sluit in:

- **History.db**: Bevat `history_visits` en `history_items` tabelle met URL's en besoek tydstempels. Gebruik `sqlite3` om te vra.
- **Downloads.plist**: Inligting oor afgelaaide lêers.
- **Bookmarks.plist**: Stoor geboekmerkte URL's.
- **TopSites.plist**: Meest besoekte webwerwe.
- **Extensions.plist**: Lys van Safari blaaiers se uitbreidings. Gebruik `plutil` of `pluginkit` om te verkry.
- **UserNotificationPermissions.plist**: Domeine wat toegelaat word om kennisgewings te stuur. Gebruik `plutil` om te parse.
- **LastSession.plist**: Oortjies van die laaste sessie. Gebruik `plutil` om te parse.
- **Browser’s built-in anti-phishing**: Kontroleer met `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. 'n Antwoord van 1 dui aan dat die funksie aktief is.

## Opera

Opera se data is geleë in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` en deel Chrome se formaat vir geskiedenis en aflaaie.

- **Browser’s built-in anti-phishing**: Verifieer deur te kontroleer of `fraud_protection_enabled` in die Voorkeurlêer op `true` gestel is met `grep`.

Hierdie paaie en opdragte is noodsaaklik vir toegang tot en begrip van die blaai data wat deur verskillende webblaaiers gestoor word.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

{{#include ../../../banners/hacktricks-training.md}}
