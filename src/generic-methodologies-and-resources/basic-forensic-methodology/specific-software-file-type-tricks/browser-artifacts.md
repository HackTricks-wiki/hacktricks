# Mabaki ya vivinjari

{{#include ../../../banners/hacktricks-training.md}}

## Mabaki ya vivinjari <a href="#id-3def" id="id-3def"></a>

Mabaki ya vivinjari ni aina mbalimbali za data zinazohifadhiwa na vivinjari vya wavuti, kama historia ya urambazaji, alama (bookmarks), na data za kache. Mabaki haya huhifadhiwa katika folda maalum ndani ya mfumo wa uendeshaji, ambapo mahali na majina yanatofautiana kati ya vivinjari, lakini kwa ujumla huwa yana aina sawa za data.

Hapa kuna muhtasari wa mabaki ya vivinjari yanayotokea mara kwa mara:

- **Navigation History**: Inarekodi ziara za mtumiaji kwenye tovuti, muhimu kwa kubaini ziara za tovuti hatarishi.
- **Autocomplete Data**: Mapendekezo yanayotokana na utafutaji wa mara kwa mara, yanaweza kutoa ufahamu ikichanganywa na historia ya urambazaji.
- **Bookmarks**: Tovuti zilizohifadhiwa na mtumiaji kwa ufikivu wa haraka.
- **Extensions and Add-ons**: Viendelezi au add-ons vilivyowekwa na mtumiaji.
- **Cache**: Huhifadhi yaliyomo ya wavuti (mfano: picha, faili za JavaScript) ili kuboresha nyakati za kupakia tovuti, muhimu kwa uchunguzi wa forensiki.
- **Logins**: Taarifa za kuingia zilizohifadhiwa.
- **Favicons**: Ikoni zinazohusishwa na tovuti, zinazoonekana kwenye tabo na alama, zikitumika kutoa taarifa za ziada kuhusu ziara za mtumiaji.
- **Browser Sessions**: Data zinazohusiana na vikao vya kivinjari vilivyo wazi.
- **Downloads**: Rekodi za faili zilizopakuliwa kupitia kivinjari.
- **Form Data**: Taarifa zilizowekwa katika fomu za wavuti, zilizoifadhiwa kwa mapendekezo ya kujaza moja kwa moja baadaye.
- **Thumbnails**: Picha ndogo za awali (thumbnails) za tovuti.
- **Custom Dictionary.txt**: Maneno yaliyoongezwa na mtumiaji kwenye kamusi ya kivinjari.

## Firefox

Firefox huweka data za mtumiaji ndani ya profaili, zinazohifadhiwa katika maeneo maalum kulingana na mfumo wa uendeshaji:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Faili `profiles.ini` ndani ya direktori hizi inaorodhesha profaili za watumiaji. Data ya kila profaili huhifadhiwa katika folda iliyoitwa kwenye thamani ya `Path` ndani ya `profiles.ini`, iliyopo katika direktori ile ile na `profiles.ini`. Ikiwa folda ya profaili inakosekana, inaweza kuwa imefutwa.

Ndani ya kila folda ya profaili, unaweza kupata faili kadhaa muhimu:

- **places.sqlite**: Inahifadhi historia, alama (bookmarks), na upakuaji. Zana kama [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kwenye Windows zinaweza kupata data ya historia.
- Tumia maswali maalum ya SQL kupata habari za historia na upakuaji.
- **bookmarkbackups**: Ina nakala za akiba za alama (bookmarks).
- **formhistory.sqlite**: Inahifadhi data za fomu za wavuti.
- **handlers.json**: Inasimamia handlers za itifaki.
- **persdict.dat**: Maneno ya kamusi ya mtumiaji.
- **addons.json** na **extensions.sqlite**: Taarifa kuhusu add-ons na viendelezi vilivyowekwa.
- **cookies.sqlite**: Uhifadhi wa cookie, ambapo [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) inapatikana kwa uchunguzi kwenye Windows.
- **cache2/entries** or **startupCache**: Data za kache, zinazoonekana kwa zana kama [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Inahifadhi favicons.
- **prefs.js**: Mipangilio na upendeleo wa mtumiaji.
- **downloads.sqlite**: Hifadhi ya zamani ya upakuaji, sasa imeingizwa ndani ya places.sqlite.
- **thumbnails**: Picha ndogo (thumbnails) za tovuti.
- **logins.json**: Taarifa za kuingia zilizofichwa (encrypted).
- **key4.db** or **key3.db**: Inahifadhi funguo za encryption kwa kulinda taarifa nyeti.

Zaidi ya hayo, kuangalia mipangilio ya kuzuia phishing ya kivinjari inaweza kufanywa kwa kutafuta vifungu `browser.safebrowsing` katika `prefs.js`, vinavyoonyesha ikiwa vipengele vya safe browsing vimewezeshwa au vimezimwa.

To try to decrypt the master password, you can use [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Kwa script na wito ifuatayo unaweza kuainisha faili la nenosiri kwa kujaribu kwa brute force:
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

Google Chrome huhifadhi profiles za watumiaji katika maeneo maalum kulingana na mfumo wa uendeshaji:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Ndani ya direktorii hizi, data nyingi za mtumiaji zinaweza kupatikana katika folda za **Default/** au **ChromeDefaultData/**. Faili zifuatazo zina data muhimu:

- **History**: Ina URLs, downloads, na maneno ya utafutaji. On Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) inaweza kutumika kusoma history. Safu ya "Transition Type" ina maana mbalimbali, ikiwa ni pamoja na bonyezo la mtumiaji kwenye link, URLs zilizotiwa kwa mkono, uwasilishaji wa fomu, na reload za ukurasa.
- **Cookies**: Inahifadhi cookies. Kwa uchunguzi, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) inapatikana.
- **Cache**: Inahifadhi data zilizokatwa. Kwa kuzijaribu, watumiaji wa Windows wanaweza kutumia [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Electron-based desktop apps (mfano, Discord) pia hutumia Chromium Simple Cache na huacha artifacts tajiri kwenye disk. Angalia:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Bookmarks za mtumiaji.
- **Web Data**: Ina historia ya fomu.
- **Favicons**: Inahifadhi favicons za tovuti.
- **Login Data**: Inajumuisha taarifa za kuingia kama usernames na passwords.
- **Current Session**/**Current Tabs**: Data kuhusu session ya sasa ya kuvinjari na tab zilizo wazi.
- **Last Session**/**Last Tabs**: Taarifa kuhusu tovuti zilifanya kazi katika session iliyopita kabla ya Chrome kufungwa.
- **Extensions**: Direktorii za extensions na addons za browser.
- **Thumbnails**: Inahifadhi thumbnails za tovuti.
- **Preferences**: Faili iliyo na habari nyingi, ikijumuisha mipangilio ya plugins, extensions, pop-ups, notifications, na mengineyo.
- **Browser’s built-in anti-phishing**: Ili kuangalia kama anti-phishing na ulinzi wa malware vimezimwa au vimewezeshwa, run `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Tafuta `{"enabled: true,"}` katika output.

## **SQLite DB Data Recovery**

Kama unavyoona katika sehemu zilizo hapo juu, Chrome na Firefox zote hutumia database za **SQLite** kuhifadhi data. Inawezekana **kupata entries zilizofutwa kwa kutumia zana** [**sqlparse**](https://github.com/padfoot999/sqlparse) **au** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 inasimamia data na metadata yake katika maeneo mbalimbali, ikiwezesha kugawanya taarifa zilizohifadhiwa na maelezo yake kwa ufikikaji na usimamizi rahisi.

### Uhifadhi wa Metadata

Metadata ya Internet Explorer imehifadhiwa katika `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (ambapo VX ni V01, V16, au V24). Pamoja na hili, faili ya `V01.log` inaweza kuonyesha tofauti za muda wa mabadiliko ikilinganishwa na `WebcacheVX.data`, jambo linaloonyesha hitaji la ukarabati kwa kutumia `esentutl /r V01 /d`. Metadata hii, iliyohifadhiwa katika ESE database, inaweza kurejeshwa na kuchunguzwa kwa zana kama photorec na [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), mtawalia. Ndani ya jedwali la **Containers**, unaweza kutambua meza maalum au containers ambazo kila kipande cha data kimehifadhiwa, ikijumuisha maelezo ya cache kwa zana nyingine za Microsoft kama Skype.

### Uchunguzi wa Cache

Zana ya [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) inaruhusu uchunguzi wa cache, na inahitaji eneo la folder la uondoaji wa data za cache. Metadata ya cache inajumuisha jina la faili, directory, idadi ya upatikanaji, chanzo cha URL, na timestamps zinazoonyesha uundaji wa cache, upatikanaji, mabadiliko, na wakati wa kumalizika.

### Usimamizi wa Cookies

Cookies zinaweza kuchunguzwa kwa kutumia [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), na metadata inajumuisha majina, URLs, idadi ya upatikanaji, na maandishi mbalimbali yanayohusiana na muda. Cookies za kudumu zipo katika `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, huku session cookies zikikaa katika memory.

### Maelezo ya Downloads

Metadata za downloads zinapatikana kupitia [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), na containers maalum zina data kama URL, aina ya faili, na eneo la download. Faili halisi zinaweza kupatikana chini ya `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Ili kupitia browsing history, unaweza kutumia [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), ikihitaji eneo la faili za history zilizochukuliwa na usanidi kwa Internet Explorer. Metadata hapa inajumuisha nyakati za mabadiliko na upatikanaji, pamoja na idadi ya upatikanaji. Faili za history ziko katika `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Typed URLs na nyakati za matumizi yamehifadhiwa ndani ya registry chini ya NTUSER.DAT katika `Software\Microsoft\InternetExplorer\TypedURLs` na `Software\Microsoft\InternetExplorer\TypedURLsTime`, zikifuatilia URLs 50 za mwisho zilizowekwa na mtumiaji na nyakati zao za mwisho za kuingiza.

## Microsoft Edge

Microsoft Edge huhifadhi data za mtumiaji katika `%userprofile%\Appdata\Local\Packages`. Njia za aina mbalimbali za data ni:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Data za Safari ziko katika `/Users/$User/Library/Safari`. Faili muhimu ni pamoja na:

- **History.db**: Inajumuisha jedwali za `history_visits` na `history_items` zenye URLs na timestamps za ziara. Tumia `sqlite3` kuendesha query.
- **Downloads.plist**: Taarifa kuhusu faili zilizopakuliwa.
- **Bookmarks.plist**: Inahifadhi URLs zilizohifadhiwa kama bookmark.
- **TopSites.plist**: Tovuti zinazozungukwa mara nyingi.
- **Extensions.plist**: Orodha ya extensions za browser ya Safari. Tumia `plutil` au `pluginkit` kupata.
- **UserNotificationPermissions.plist**: Domain zilizoidhinishwa kutuma notifications. Tumia `plutil` kusoma.
- **LastSession.plist**: Tabs kutoka kwa session ya mwisho. Tumia `plutil` kusoma.
- **Browser’s built-in anti-phishing**: Angalia kwa kutumia `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Jibu la 1 linaonyesha kipengele kimewekwa.

## Opera

Data za Opera zipo katika `/Users/$USER/Library/Application Support/com.operasoftware.Opera` na zina muundo sawa na wa Chrome kwa history na downloads.

- **Browser’s built-in anti-phishing**: Thibitisha kwa kuangalia kama `fraud_protection_enabled` katika faili la Preferences imewekwa kuwa `true` kwa kutumia `grep`.

Njia hizi na amri ni muhimu kwa kufikia na kuelewa data za kuvinjari zinazohifadhiwa na browsers mbalimbali.

## Marejeleo

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**


{{#include ../../../banners/hacktricks-training.md}}
