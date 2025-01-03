# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Browsers Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artifacts ni pamoja na aina mbalimbali za data zilizohifadhiwa na vivinjari vya wavuti, kama vile historia ya urambazaji, alama, na data ya cache. Vifaa hivi vinahifadhiwa katika folda maalum ndani ya mfumo wa uendeshaji, vinatofautiana katika eneo na jina kati ya vivinjari, lakini kwa ujumla vinahifadhi aina sawa za data.

Hapa kuna muhtasari wa vifaa vya vivinjari vinavyotumika zaidi:

- **Historia ya Urambazaji**: Inafuatilia ziara za mtumiaji kwenye tovuti, muhimu kwa kutambua ziara kwenye tovuti za uhalifu.
- **Data ya Autocomplete**: Mapendekezo yanayotokana na utafutaji wa mara kwa mara, yanayotoa mwanga unapounganishwa na historia ya urambazaji.
- **Alama**: Tovuti zilizohifadhiwa na mtumiaji kwa ufikiaji wa haraka.
- **Extensions na Add-ons**: Mipanuzi ya vivinjari au add-ons zilizowekwa na mtumiaji.
- **Cache**: Inahifadhi maudhui ya wavuti (mfano, picha, faili za JavaScript) ili kuboresha nyakati za upakiaji wa tovuti, muhimu kwa uchambuzi wa forensics.
- **Logins**: Akiba ya taarifa za kuingia.
- **Favicons**: Icons zinazohusishwa na tovuti, zinazoonekana kwenye tab na alama, muhimu kwa taarifa za ziada kuhusu ziara za mtumiaji.
- **Sessions za Vivinjari**: Data inayohusiana na sessions za vivinjari zilizo wazi.
- **Downloads**: Rekodi za faili zilizopakuliwa kupitia vivinjari.
- **Data za Fomu**: Taarifa zilizoingizwa kwenye fomu za wavuti, zilizohifadhiwa kwa mapendekezo ya autofill ya baadaye.
- **Thumbnails**: Picha za awali za tovuti.
- **Custom Dictionary.txt**: Maneno yaliyoongezwa na mtumiaji kwenye kamusi ya kivinjari.

## Firefox

Firefox inaandaa data za mtumiaji ndani ya profaili, zilizohifadhiwa katika maeneo maalum kulingana na mfumo wa uendeshaji:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Faili ya `profiles.ini` ndani ya hizi folda inataja profaili za mtumiaji. Data za kila profaili huhifadhiwa katika folda iliyo na jina katika variable ya `Path` ndani ya `profiles.ini`, iliyoko katika saraka sawa na `profiles.ini` yenyewe. Ikiwa folda ya profaili inakosekana, inaweza kuwa imefutwa.

Ndani ya kila folda ya profaili, unaweza kupata faili kadhaa muhimu:

- **places.sqlite**: Inahifadhi historia, alama, na downloads. Zana kama [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kwenye Windows zinaweza kufikia data ya historia.
- Tumia maswali maalum ya SQL kutoa taarifa za historia na downloads.
- **bookmarkbackups**: Inahifadhi nakala za alama.
- **formhistory.sqlite**: Inahifadhi data za fomu za wavuti.
- **handlers.json**: Inasimamia wakala wa itifaki.
- **persdict.dat**: Maneno ya kamusi ya kawaida.
- **addons.json** na **extensions.sqlite**: Taarifa kuhusu add-ons na mipanuzi iliyowekwa.
- **cookies.sqlite**: Hifadhi ya kuki, na [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) inapatikana kwa ukaguzi kwenye Windows.
- **cache2/entries** au **startupCache**: Data ya cache, inayoweza kupatikana kupitia zana kama [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Inahifadhi favicons.
- **prefs.js**: Mipangilio na mapendeleo ya mtumiaji.
- **downloads.sqlite**: Hifadhi ya zamani ya downloads, sasa imeunganishwa kwenye places.sqlite.
- **thumbnails**: Thumbnails za tovuti.
- **logins.json**: Taarifa za kuingia zilizofichwa.
- **key4.db** au **key3.db**: Inahifadhi funguo za usimbaji kwa ajili ya kulinda taarifa nyeti.

Zaidi ya hayo, kuangalia mipangilio ya kivinjari ya kupambana na uhalifu wa mtandao kunaweza kufanywa kwa kutafuta `browser.safebrowsing` katika `prefs.js`, ikionyesha ikiwa vipengele vya kuvinjari salama vimewezeshwa au havijawezeshwa.

Ili kujaribu kufichua nenosiri kuu, unaweza kutumia [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Kwa script na wito huu unaweza kubainisha faili la nenosiri ili kufanya brute force:
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

Google Chrome huhifadhi profaili za watumiaji katika maeneo maalum kulingana na mfumo wa uendeshaji:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Ndani ya hizi directories, data nyingi za mtumiaji zinaweza kupatikana katika folda za **Default/** au **ChromeDefaultData/**. Faili zifuatazo zina data muhimu:

- **History**: Inashikilia URLs, downloads, na maneno ya utafutaji. Kwenye Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) inaweza kutumika kusoma historia. Safu ya "Transition Type" ina maana mbalimbali, ikiwa ni pamoja na kubonyeza kwa watumiaji kwenye viungo, URLs zilizotajwa, uwasilishaji wa fomu, na upakiaji wa kurasa.
- **Cookies**: Inahifadhi cookies. Kwa ukaguzi, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) inapatikana.
- **Cache**: Inashikilia data iliyohifadhiwa. Ili kukagua, watumiaji wa Windows wanaweza kutumia [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).
- **Bookmarks**: Alama za mtumiaji.
- **Web Data**: Inashikilia historia ya fomu.
- **Favicons**: Inahifadhi favicons za tovuti.
- **Login Data**: Inajumuisha taarifa za kuingia kama vile majina ya watumiaji na nywila.
- **Current Session**/**Current Tabs**: Data kuhusu kikao cha sasa cha kuvinjari na tabo zilizo wazi.
- **Last Session**/**Last Tabs**: Taarifa kuhusu tovuti zilizokuwa hai wakati wa kikao cha mwisho kabla ya Chrome kufungwa.
- **Extensions**: Maktaba za nyongeza za kivinjari na addons.
- **Thumbnails**: Inahifadhi thumbnails za tovuti.
- **Preferences**: Faili yenye taarifa nyingi, ikiwa ni pamoja na mipangilio ya plugins, nyongeza, pop-ups, arifa, na zaidi.
- **Browser’s built-in anti-phishing**: Ili kuangalia kama ulinzi wa kupambana na phishing na malware umewezeshwa, endesha `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Tafuta `{"enabled: true,"}` katika matokeo.

## **SQLite DB Data Recovery**

Kama unavyoona katika sehemu zilizopita, Chrome na Firefox zote zinatumia **SQLite** databases kuhifadhi data. Inawezekana **kurejesha entries zilizofutwa kwa kutumia zana** [**sqlparse**](https://github.com/padfoot999/sqlparse) **au** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 inasimamia data zake na metadata katika maeneo mbalimbali, ikisaidia kutenganisha taarifa zilizohifadhiwa na maelezo yake yanayohusiana kwa urahisi wa ufikiaji na usimamizi.

### Metadata Storage

Metadata kwa Internet Explorer inahifadhiwa katika `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (ikiwa VX ni V01, V16, au V24). Pamoja na hii, faili ya `V01.log` inaweza kuonyesha tofauti za muda wa mabadiliko na `WebcacheVX.data`, ikionyesha hitaji la kurekebisha kwa kutumia `esentutl /r V01 /d`. Metadata hii, iliyohifadhiwa katika database ya ESE, inaweza kurejeshwa na kukaguliwa kwa kutumia zana kama photorec na [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), mtawalia. Ndani ya jedwali la **Containers**, mtu anaweza kutambua jedwali maalum au vyombo ambavyo kila sehemu ya data imehifadhiwa, ikiwa ni pamoja na maelezo ya cache kwa zana nyingine za Microsoft kama Skype.

### Cache Inspection

Zana ya [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) inaruhusu ukaguzi wa cache, ikihitaji eneo la folda ya uchimbaji wa data ya cache. Metadata ya cache inajumuisha jina la faili, directory, idadi ya ufikiaji, asili ya URL, na alama za wakati zinazoashiria uundaji wa cache, ufikiaji, mabadiliko, na nyakati za kuisha.

### Cookies Management

Cookies zinaweza kuchunguzwa kwa kutumia [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), huku metadata ikijumuisha majina, URLs, idadi ya ufikiaji, na maelezo mbalimbali yanayohusiana na wakati. Cookies za kudumu huhifadhiwa katika `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, huku cookies za kikao zikiwa katika kumbukumbu.

### Download Details

Metadata ya downloads inapatikana kupitia [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), huku vyombo maalum vikihifadhi data kama URL, aina ya faili, na eneo la upakuaji. Faili halisi zinaweza kupatikana chini ya `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Ili kupitia historia ya kuvinjari, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) inaweza kutumika, ikihitaji eneo la faili za historia zilizochimbwa na usanidi kwa Internet Explorer. Metadata hapa inajumuisha nyakati za mabadiliko na ufikiaji, pamoja na idadi ya ufikiaji. Faili za historia ziko katika `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

URLs zilizotajwa na nyakati zao za matumizi zimehifadhiwa ndani ya rejista chini ya `NTUSER.DAT` katika `Software\Microsoft\InternetExplorer\TypedURLs` na `Software\Microsoft\InternetExplorer\TypedURLsTime`, zikifuatilia URLs 50 za mwisho zilizotajwa na mtumiaji na nyakati zao za mwisho za kuingizwa.

## Microsoft Edge

Microsoft Edge huhifadhi data za watumiaji katika `%userprofile%\Appdata\Local\Packages`. Njia za aina mbalimbali za data ni:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Data za Safari huhifadhiwa katika `/Users/$User/Library/Safari`. Faili muhimu ni:

- **History.db**: Inashikilia jedwali la `history_visits` na `history_items` zikiwa na URLs na alama za wakati wa kutembelea. Tumia `sqlite3` kuuliza.
- **Downloads.plist**: Taarifa kuhusu faili zilizopakuliwa.
- **Bookmarks.plist**: Inahifadhi URLs zilizowekwa alama.
- **TopSites.plist**: Tovuti zinazotembelewa mara nyingi.
- **Extensions.plist**: Orodha ya nyongeza za kivinjari cha Safari. Tumia `plutil` au `pluginkit` kupata.
- **UserNotificationPermissions.plist**: Domains zilizoidhinishwa kutuma arifa. Tumia `plutil` kuchambua.
- **LastSession.plist**: Tabo kutoka kikao cha mwisho. Tumia `plutil` kuchambua.
- **Browser’s built-in anti-phishing**: Angalia kwa kutumia `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Jibu la 1 linaashiria kuwa kipengele hiki kimewezeshwa.

## Opera

Data za Opera ziko katika `/Users/$USER/Library/Application Support/com.operasoftware.Opera` na inashiriki muundo wa Chrome kwa historia na upakuaji.

- **Browser’s built-in anti-phishing**: Thibitisha kwa kuangalia kama `fraud_protection_enabled` katika faili ya Preferences imewekwa kuwa `true` kwa kutumia `grep`.

Njia hizi na amri ni muhimu kwa ufikiaji na kuelewa data za kuvinjari zilizohifadhiwa na vivinjari tofauti vya wavuti.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

{{#include ../../../banners/hacktricks-training.md}}
