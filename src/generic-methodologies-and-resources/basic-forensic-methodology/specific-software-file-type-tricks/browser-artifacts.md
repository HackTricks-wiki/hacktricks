# Mabaki ya Browser

{{#include ../../../banners/hacktricks-training.md}}

## Mabaki ya Browsers <a href="#id-3def" id="id-3def"></a>

Mabaki ya browser yanajumuisha aina mbalimbali za data zinazohifadhiwa na browsers, kama vile historia ya uvinjari, bookmarks, na data ya cache. Mabaki haya huhifadhiwa katika folda maalum ndani ya operating system, zikitofautiana kwa eneo na jina kati ya browsers, lakini kwa ujumla zikihifadhi aina zinazofanana za data.

Huu hapa muhtasari wa mabaki ya browser yanayotumika zaidi:

- **Historia ya Uvinjari**: Hufuatilia ziara za mtumiaji kwenye websites, na ni muhimu kwa kutambua ziara kwenye websites hasidi.
- **Data ya Autocomplete**: Mapendekezo yanayotokana na utafutaji wa mara kwa mara, yanayoweza kutoa maarifa yanapojumuishwa na historia ya uvinjari.
- **Bookmarks**: Websites zilizohifadhiwa na mtumiaji kwa ajili ya kuzifikia haraka.
- **Extensions na Add-ons**: Browser extensions au add-ons zilizosakinishwa na mtumiaji.
- **Cache**: Huhifadhi maudhui ya web (kwa mfano, images na JavaScript files) ili kuboresha muda wa kupakia websites, na ni muhimu kwa forensic analysis.
- **Logins**: Login credentials zilizohifadhiwa.
- **Favicons**: Icons zinazohusishwa na websites, zinazoonekana kwenye tabs na bookmarks, na ni muhimu kwa kupata taarifa za ziada kuhusu ziara za mtumiaji.
- **Browser Sessions**: Data inayohusiana na browser sessions zilizo wazi.
- **Downloads**: Rekodi za files zilizopakuliwa kupitia browser.
- **Form Data**: Taarifa zilizoingizwa kwenye web forms, zilizohifadhiwa kwa ajili ya mapendekezo ya baadaye ya autofill.
- **Thumbnails**: Images za preview za websites.
- **Custom Dictionary.txt**: Maneno yaliyoongezwa na mtumiaji kwenye dictionary ya browser.

## Firefox

Firefox hupanga data ya mtumiaji ndani ya profiles, zinazohifadhiwa katika maeneo maalum kulingana na operating system:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

File ya `profiles.ini` ndani ya directories hizi huorodhesha user profiles. Data ya kila profile huhifadhiwa kwenye folder lililopewa jina katika variable ya `Path` ndani ya `profiles.ini`, lililopo kwenye directory moja na file ya `profiles.ini` lenyewe. Ikiwa folder la profile halipo, huenda lilifutwa.

Ndani ya kila profile folder, unaweza kupata files kadhaa muhimu:<sup>[[1]](#references)</sup>

- **places.sqlite**: Huhifadhi history, bookmarks, na downloads. Tools kama [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kwenye Windows zinaweza kufikia data ya history.
- Tumia SQL queries maalum kutoa taarifa za history na downloads.
- **bookmarkbackups**: Ina backups za bookmarks.
- **formhistory.sqlite**: Huhifadhi data ya web forms.
- **handlers.json**: Hudhibiti protocol handlers.
- **persdict.dat**: Maneno ya custom dictionary.
- **addons.json** na **extensions.sqlite**: Taarifa kuhusu add-ons na extensions zilizosakinishwa.
- **cookies.sqlite**: Huhifadhi cookies, huku [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) ikiwa available kwa ajili ya inspection kwenye Windows.
- **cache2/entries** au **startupCache**: Data ya cache, inayoweza kufikiwa kupitia tools kama [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Huhifadhi favicons.
- **prefs.js**: Settings na preferences za mtumiaji.
- **downloads.sqlite**: Database ya zamani ya downloads, ambayo sasa imeunganishwa kwenye places.sqlite.
- **thumbnails**: Thumbnails za websites.
- **logins.json**: Taarifa za login zilizosimbwa.
- **key4.db** au **key3.db**: Huhifadhi encryption keys kwa ajili ya kulinda taarifa nyeti.

Zaidi ya hayo, unaweza kukagua settings za browser za anti-phishing kwa kutafuta entries za `browser.safebrowsing` kwenye `prefs.js`, zinazoonyesha ikiwa vipengele vya safe browsing vimewezeshwa au kuzimwa.<sup>[[2]](#references)</sup>

Ili kujaribu kusimbua master password, unaweza kutumia [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Kwa script na call ifuatayo unaweza kubainisha password file ya kufanya brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Mabaki ya Browsers - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome huhifadhi profiles za watumiaji katika maeneo maalum kulingana na operating system:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Ndani ya directories hizi, data nyingi za mtumiaji zinaweza kupatikana katika folders za **Default/** au **ChromeDefaultData/**. Files zifuatazo zina data muhimu:<sup>[[1]](#references)</sup>

- **History**: Ina URLs, downloads, na search keywords. Kwenye Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) inaweza kutumika kusoma history. Column ya "Transition Type" ina maana mbalimbali, zikiwemo user clicks kwenye links, typed URLs, form submissions, na page reloads.
- **Cookies**: Huhifadhi cookies. Kwa inspection, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) inapatikana.
- **Cache**: Huhifadhi cached data. Kwa inspection, watumiaji wa Windows wanaweza kutumia [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Desktop apps zinazotumia Electron (kwa mfano, Discord) pia hutumia Chromium Simple Cache na kuacha on-disk artifacts nyingi. Angalia:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Bookmarks za mtumiaji.
- **Web Data**: Ina form history.
- **Favicons**: Huhifadhi website favicons.
- **Login Data**: Ina login credentials kama usernames na passwords.
- **Current Session**/**Current Tabs**: Data kuhusu browsing session ya sasa na tabs zilizo wazi.
- **Last Session**/**Last Tabs**: Taarifa kuhusu sites zilizokuwa active katika session iliyopita kabla Chrome haijafungwa.
- **Extensions**: Directories za browser extensions na addons.
- **Thumbnails**: Huhifadhi website thumbnails.
- **Preferences**: File yenye taarifa nyingi, ikiwemo settings za plugins, extensions, pop-ups, notifications, na zaidi.
- **Browser’s built-in anti-phishing**: Ili kuangalia kama anti-phishing na malware protection zimewezeshwa, endesha `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Tafuta `{"enabled: true,"}` katika output.<sup>[[2]](#references)</sup>

## **Urejeshaji wa SQLite DB Data**

Kama unavyoweza kuona katika sehemu zilizotangulia, Chrome na Firefox hutumia databases za **SQLite** kuhifadhi data. Inawezekana **kurecover entries zilizofutwa kwa kutumia tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **au** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 husimamia data na metadata yake katika maeneo mbalimbali, jambo linalosaidia kutenganisha taarifa zilizohifadhiwa na maelezo yake yanayolingana kwa ajili ya access na management rahisi.

### **Metadata Storage**

Metadata ya Internet Explorer huhifadhiwa katika `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (ambapo VX inaweza kuwa V01, V16, au V24). Sambamba na hii, file ya `V01.log` inaweza kuonyesha tofauti za modification time na `WebcacheVX.data`, ikionyesha hitaji la repair kwa kutumia `esentutl /r V01 /d`. Metadata hii, iliyohifadhiwa katika ESE database, inaweza kurecoveriwa na kukaguliwa kwa kutumia tools kama photorec na [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), mtawalia. Ndani ya table ya **Containers**, mtu anaweza kutambua tables au containers maalum ambako kila segment ya data imehifadhiwa, ikiwemo cache details za Microsoft tools nyingine kama Skype.

### **Cache Inspection**

Tool ya [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) inaruhusu inspection ya cache, na inahitaji location ya folder ya cache data extraction. Metadata ya cache inajumuisha filename, directory, access count, URL origin, na timestamps zinazoonyesha cache creation, access, modification, na expiry times.

### **Cookies Management**

Cookies zinaweza kuchunguzwa kwa kutumia [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), huku metadata ikijumuisha names, URLs, access counts, na details mbalimbali zinazohusiana na muda. Persistent cookies huhifadhiwa katika `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, huku session cookies zikihifadhiwa kwenye memory.

### **Download Details**

Downloads metadata inapatikana kupitia [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), huku containers maalum zikiwa na data kama URL, file type, na download location. Physical files zinaweza kupatikana chini ya `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### **Browsing History**

Ili kukagua browsing history, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) inaweza kutumika, na inahitaji location ya history files zilizotolewa pamoja na configuration ya Internet Explorer. Metadata hapa inajumuisha modification na access times, pamoja na access counts. History files ziko katika `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### **Typed URLs**

Typed URLs na muda wa matumizi yake huhifadhiwa ndani ya registry chini ya `NTUSER.DAT` katika `Software\Microsoft\InternetExplorer\TypedURLs` na `Software\Microsoft\InternetExplorer\TypedURLsTime`, zikifuatilia URLs 50 za mwisho zilizoingizwa na mtumiaji pamoja na nyakati za mwisho za kuingizwa.

## **Microsoft Edge**

Microsoft Edge huhifadhi user data katika `%userprofile%\Appdata\Local\Packages`. Paths za aina mbalimbali za data ni:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## **Safari**

Safari data huhifadhiwa katika `/Users/$User/Library/Safari`. Files muhimu zinajumuisha:<sup>[[3]](#references)</sup>

- **History.db**: Ina tables za `history_visits` na `history_items` zenye URLs na visit timestamps. Tumia `sqlite3` kufanya query.
- **Downloads.plist**: Taarifa kuhusu files zilizopakuliwa.
- **Bookmarks.plist**: Huhifadhi bookmarked URLs.
- **TopSites.plist**: Sites zinazotembelewa mara nyingi zaidi.
- **Extensions.plist**: Orodha ya Safari browser extensions. Tumia `plutil` au `pluginkit` kuzipata.
- **UserNotificationPermissions.plist**: Domains zinazoruhusiwa kutuma push notifications. Tumia `plutil` kuparse.
- **LastSession.plist**: Tabs kutoka session iliyopita. Tumia `plutil` kuparse.
- **Browser’s built-in anti-phishing**: Kagua kwa kutumia `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Response ya 1 inaonyesha kuwa feature hiyo iko active.<sup>[[2]](#references)</sup>

## **Opera**

Data ya Opera iko katika `/Users/$USER/Library/Application Support/com.operasoftware.Opera` na inashiriki format ya Chrome kwa history na downloads.

- **Browser’s built-in anti-phishing**: Thibitisha kwa kuangalia ikiwa `fraud_protection_enabled` katika Preferences file imewekwa kuwa `true` kwa kutumia `grep`.<sup>[[2]](#references)</sup>

Paths na commands hizi ni muhimu kwa accessing na kuelewa browsing data inayohifadhiwa na web browsers mbalimbali.

## References

- [1] [Forensics ya Web Browsers: Mwongozo wa Kufanya Forensic Analysis ya Web Browsers](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Incident Response ya macOS | Sehemu ya 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Incident Response ya OS X: Scripting na Analysis, na Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
