# Mabaki ya Kivinjari

{{#include ../../../banners/hacktricks-training.md}}

## Mabaki ya Vivinjari <a href="#id-3def" id="id-3def"></a>

Mabaki ya kivinjari yanajumuisha aina mbalimbali za data zinazohifadhiwa na vivinjari vya wavuti, kama vile historia ya urambazaji, alamisho na data ya akiba. Mabaki haya huhifadhiwa kwenye folda maalum ndani ya mfumo wa uendeshaji. Mahali na majina yake hutofautiana kati ya vivinjari, lakini kwa ujumla huhifadhi aina zinazofanana za data.

Huu hapa muhtasari wa mabaki ya kawaida zaidi ya kivinjari:

- **Historia ya Urambazaji**: Hufuatilia tovuti ambazo mtumiaji ametembelea, na ni muhimu kwa kutambua matembezi kwenye tovuti hasidi.
- **Data ya Kukamilisha Kiotomatiki**: Mapendekezo yanayotokana na utafutaji wa mara kwa mara, ambayo yakichanganywa na historia ya urambazaji yanaweza kutoa maarifa.
- **Alamisho**: Tovuti zilizohifadhiwa na mtumiaji ili azifikie kwa haraka.
- **Viendelezi na Viongezi**: Viendelezi au viongezi vya kivinjari vilivyosakinishwa na mtumiaji.
- **Akiba**: Huhifadhi maudhui ya wavuti (kwa mfano, picha na faili za JavaScript) ili kuboresha kasi ya kupakia tovuti, na ni muhimu kwa uchanganuzi wa kiuchunguzi.
- **Taarifa za Kuingia**: Sifa za kuingia zilizohifadhiwa.
- **Favicons**: Aikoni zinazohusishwa na tovuti, zinazoonekana kwenye vichupo na alamisho, na zinazoweza kutoa maelezo ya ziada kuhusu tovuti zilizotembelewa na mtumiaji.
- **Vipindi vya Kivinjari**: Data inayohusiana na vipindi vya kivinjari vilivyo wazi.
- **Vipakuliwa**: Rekodi za faili zilizopakuliwa kupitia kivinjari.
- **Data ya Fomu**: Taarifa zilizoingizwa kwenye fomu za wavuti, zilizohifadhiwa kwa ajili ya mapendekezo ya kujaza kiotomatiki baadaye.
- **Picha Tazami**: Picha za muhtasari wa tovuti.
- **Custom Dictionary.txt**: Maneno yaliyoongezwa na mtumiaji kwenye kamusi ya kivinjari.

## Firefox

Firefox hupanga data ya mtumiaji ndani ya profaili, zinazohifadhiwa katika maeneo maalum kulingana na mfumo wa uendeshaji:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Faili ya `profiles.ini` ndani ya saraka hizi huorodhesha profaili za mtumiaji. Data ya kila profaili huhifadhiwa kwenye folda ambayo jina lake limebainishwa katika kigezo cha `Path` ndani ya `profiles.ini`, iliyo kwenye saraka sawa na faili ya `profiles.ini` yenyewe. Ikiwa folda ya profaili haipo, huenda ilifutwa.

Ndani ya kila folda ya profaili, unaweza kupata faili kadhaa muhimu:<sup>[[1]](#references)</sup>

- **places.sqlite**: Huhifadhi historia, alamisho na vipakuliwa. Zana kama [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kwenye Windows zinaweza kufikia data ya historia.
  - Tumia SQL queries maalum kutoa taarifa za historia na vipakuliwa.
- **bookmarkbackups**: Ina nakala rudufu za alamisho.
- **formhistory.sqlite**: Huhifadhi data ya fomu za wavuti.
- **handlers.json**: Hudhibiti vidhibiti vya protocol.
- **persdict.dat**: Maneno ya kamusi maalum.
- **addons.json** na **extensions.sqlite**: Taarifa kuhusu viongezi na viendelezi vilivyosakinishwa.
- **cookies.sqlite**: Huhifadhi cookies; [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) inaweza kutumika kuzichunguza kwenye Windows.
- **cache2/entries** au **startupCache**: Data ya akiba, inayoweza kufikiwa kwa zana kama [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Huhifadhi favicons.
- **prefs.js**: Mipangilio na mapendeleo ya mtumiaji.
- **downloads.sqlite**: Hifadhidata ya zamani ya vipakuliwa, ambayo sasa imeunganishwa kwenye places.sqlite.
- **thumbnails**: Picha tazami za tovuti.
- **logins.json**: Taarifa za kuingia zilizosimbwa kwa njia fiche.
- **key4.db** au **key3.db**: Huhifadhi funguo za usimbaji fiche zinazotumika kulinda taarifa nyeti.

Aidha, unaweza kukagua mipangilio ya Firefox ya kuzuia hadaa kwa kutafuta maingizo ya `browser.safebrowsing` kwenye `prefs.js`. Maingizo hayo huonyesha ikiwa vipengele vya kuvinjari kwa usalama vimewashwa au vimezimwa.<sup>[[2]](#references)</sup>

Ili kufungua taarifa za kuingia zilizohifadhiwa kutoka kwenye profaili unayoweza kufikia, lazima utoe au urejeshe kando [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), ikiwa iliwekwa; profaili yenyewe haiwezi kufichua nenosiri hilo. Thibitisha kwamba taarifa zozote za kuingia zilizorejeshwa zinawezesha kuingia kwenye akaunti yake ya wavuti. Ufikiaji wa root kwenye Unix unahitaji uthibitisho tofauti kwamba sifa hiyo pia inakubaliwa na mfumo wa uthibitishaji wa Unix kwa root. Unaweza kukagua taarifa za kuingia zilizohifadhiwa kwa kutumia [firefox_decrypt](https://github.com/unode/firefox_decrypt). Mfano ufuatao hujaribu manenosiri ya Primary Password yanayowezekana kutoka kwenye faili ya manenosiri:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Mabaki ya Vivinjari - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome huhifadhi profaili za watumiaji katika maeneo mahususi kulingana na mfumo wa uendeshaji:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Ndani ya saraka hizi, data nyingi za watumiaji hupatikana kwenye folda za **Default/** au **ChromeDefaultData/**. Faili zifuatazo zina data muhimu:<sup>[[1]](#references)</sup>

- **Historia**: Ina URL, vipakuliwa na maneno muhimu ya utafutaji. Kwenye Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) inaweza kutumika kusoma historia. Safu ya "Transition Type" ina maana mbalimbali, ikiwemo mtumiaji kubofya viungo, kuandika URL, kuwasilisha fomu na kupakia upya kurasa.
- **Cookies**: Huhifadhi cookies. Kwa ukaguzi, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) inapatikana.
- **Cache**: Huhifadhi data ya muda. Kwa ukaguzi, watumiaji wa Windows wanaweza kutumia [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Programu za kompyuta za mezani zinazotumia Electron (kwa mfano, Discord) pia hutumia Chromium Simple Cache na huacha mabaki mengi kwenye diski. Tazama:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Alamisho**: Alamisho za mtumiaji.
- **Web Data**: Ina historia ya fomu.
- **Favicons**: Huhifadhi favicons za tovuti.
- **Login Data**: Ina taarifa za kuingia, kama majina ya watumiaji na manenosiri.
- **Current Session**/**Current Tabs**: Data kuhusu kipindi cha sasa cha kuvinjari na vichupo vilivyo wazi.
- **Last Session**/**Last Tabs**: Taarifa kuhusu tovuti zilizokuwa wazi katika kipindi cha mwisho kabla Chrome haijafungwa.
- **Extensions**: Saraka za viendelezi na addons za kivinjari.
- **Thumbnails**: Huhifadhi vijipicha vya tovuti.
- **Preferences**: Faili yenye taarifa nyingi, ikiwemo mipangilio ya plugins, viendelezi, madirisha ibukizi, arifa na mengineyo.
- **Kinga dhidi ya phishing iliyojengewa ndani ya kivinjari**: Ili kuangalia kama kinga dhidi ya phishing na programu hasidi imewashwa, endesha `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Tafuta `{"enabled: true,"}` kwenye matokeo.<sup>[[2]](#references)</sup>

Saraka ya `Local Extension Settings/<extension-id>/` katika profaili ya Chromium inaweza kuwa na hali ya ndani ya kiendelezi, ikiwemo nyenzo muhimu za ufunguo za kidhibiti cha manenosiri. Kwa mfano, [Passbolt inasema ufunguo wake binafsi uliosimbwa kwa njia fiche huhifadhiwa katika hifadhi ya ndani ya kiendelezi cha kivinjari](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), na [Chrome extension ID yake](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) hubainisha saraka husika. Kuwepo kwa saraka pekee hakuthibitishi kuwa ufunguo upo wala hakufungui vault: mtumiaji lazima awe na ufikiaji wa data ya profaili, ufunguo binafsi na passphrase zinazoweza kutumika, pamoja na njia iliyoidhinishwa ya kurejesha au kuthibitisha utambulisho kwa seva. Kipengee cha vault chenye nenosiri la akaunti ya mfumo wa uendeshaji kinahitaji uthibitishaji tofauti wa matumizi tena ya akaunti. Uorodheshaji wa kawaida unapaswa kuripoti tu njia ya hifadhi, bila kutoa faili zake za LevelDB au thamani za siri.

## **Urejeshaji wa Data ya SQLite DB**

Kama unavyoona katika sehemu zilizotangulia, Chrome na Firefox hutumia hifadhidata za **SQLite** kuhifadhi data. Inawezekana **kurejesha rekodi zilizofutwa kwa kutumia zana** [**sqlparse**](https://github.com/padfoot999/sqlparse) **au** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 hudhibiti data na metadata yake katika maeneo mbalimbali, ili kutenganisha taarifa zilizohifadhiwa na maelezo yake husika kwa ajili ya ufikiaji na usimamizi rahisi.

### Hifadhi ya Metadata

Metadata ya Internet Explorer huhifadhiwa katika `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (ambapo VX ni V01, V16, au V24). Faili ya `V01.log` inayoandamana nayo inaweza kuonyesha kutolingana kwa muda wa urekebishaji na `WebcacheVX.data`, ikionyesha kuwa huenda faili inahitaji kurekebishwa kwa kutumia `esentutl /r V01 /d`. Metadata hii, iliyohifadhiwa kwenye hifadhidata ya ESE, inaweza kurejeshwa na kukaguliwa kwa kutumia zana kama photorec na [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), mtawalia. Katika jedwali la **Containers**, unaweza kutambua jedwali au kontena mahususi ambamo kila sehemu ya data imehifadhiwa, ikiwemo maelezo ya cache ya zana nyingine za Microsoft kama Skype.

### Ukaguzi wa Cache

Zana ya [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) huruhusu ukaguzi wa cache, na huhitaji eneo la folda ambamo data ya cache imetolewa. Metadata ya cache inajumuisha jina la faili, saraka, idadi ya ufikiaji, chanzo cha URL na mihuri ya muda inayoonyesha nyakati za kuundwa, kufikiwa, kurekebishwa na kuisha kwa cache.

### Usimamizi wa Cookies

Cookies zinaweza kuchunguzwa kwa kutumia [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), huku metadata yake ikijumuisha majina, URL, idadi ya ufikiaji na maelezo mbalimbali yanayohusiana na muda. Cookies za kudumu huhifadhiwa katika `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, huku cookies za kipindi zikihifadhiwa kwenye kumbukumbu.

### Maelezo ya Vipakuliwa

Metadata ya vipakuliwa inapatikana kupitia [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), huku kontena mahususi zikihifadhi data kama URL, aina ya faili na eneo la upakuaji. Faili halisi zinaweza kupatikana katika `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historia ya Kuvinjari

Ili kukagua historia ya kuvinjari, unaweza kutumia [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), ambayo huhitaji eneo la faili za historia zilizotolewa na usanidi wa Internet Explorer. Metadata hapa inajumuisha nyakati za urekebishaji na ufikiaji, pamoja na idadi ya ufikiaji. Faili za historia ziko katika `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL Zilizoandikwa

URL zilizoandikwa na nyakati za matumizi yake huhifadhiwa kwenye registry chini ya `NTUSER.DAT` katika `Software\Microsoft\InternetExplorer\TypedURLs` na `Software\Microsoft\InternetExplorer\TypedURLsTime`. Hufuatilia URL 50 za mwisho zilizoingizwa na mtumiaji na nyakati za mwisho zilipoingizwa.

## Microsoft Edge

Microsoft Edge huhifadhi data ya mtumiaji katika `%userprofile%\Appdata\Local\Packages`. Njia za aina mbalimbali za data ni:<sup>[[1]](#references)</sup>

- **Njia ya Profaili**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Historia, Cookies na Vipakuliwa**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Mipangilio, Alamisho na Orodha ya Kusoma**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Vipindi Vilivyotumika Hivi Karibuni**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Data ya Safari huhifadhiwa katika `/Users/$User/Library/Safari`. Faili muhimu ni:<sup>[[3]](#references)</sup>

- **History.db**: Ina jedwali za `history_visits` na `history_items` zenye URL na mihuri ya muda ya ziara. Tumia `sqlite3` kuuliza data.
- **Downloads.plist**: Taarifa kuhusu faili zilizopakuliwa.
- **Bookmarks.plist**: Huhifadhi URL zilizoalamishwa.
- **TopSites.plist**: Tovuti zinazotembelewa mara nyingi zaidi.
- **Extensions.plist**: Orodha ya viendelezi vya kivinjari cha Safari. Tumia `plutil` au `pluginkit` kuvipata.
- **UserNotificationPermissions.plist**: Domain zinazoruhusiwa kutuma arifa. Tumia `plutil` kuchanganua.
- **LastSession.plist**: Vichupo kutoka kipindi cha mwisho. Tumia `plutil` kuchanganua.
- **Kinga dhidi ya phishing iliyojengewa ndani ya kivinjari**: Angalia kwa kutumia `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Jibu la 1 linaonyesha kuwa kipengele hiki kimewashwa.<sup>[[2]](#references)</sup>

## Opera

Data ya Opera iko katika `/Users/$USER/Library/Application Support/com.operasoftware.Opera` na hutumia umbizo sawa na Chrome kwa historia na vipakuliwa.

- **Kinga dhidi ya phishing iliyojengewa ndani ya kivinjari**: Thibitisha kwa kuangalia kama `fraud_protection_enabled` katika faili ya Preferences imewekwa kuwa `true`, kwa kutumia `grep`.<sup>[[2]](#references)</sup>

Njia na amri hizi ni muhimu kwa kufikia na kuelewa data ya kuvinjari iliyohifadhiwa na vivinjari mbalimbali vya wavuti.

## References

- [1] [Uchunguzi wa Kiforensiki wa Vivinjari vya Wavuti: Mwongozo wa Kufanya Uchambuzi wa Kiforensiki wa Vivinjari vya Wavuti](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Majibu kwa Matukio ya macOS | Sehemu ya 3: Udanganyifu wa Mfumo](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Majibu kwa Matukio ya OS X: Uandishi wa Skripti na Uchambuzi na Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
