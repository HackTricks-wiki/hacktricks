# Mabaki ya Browser

{{#include ../../../banners/hacktricks-training.md}}

## Mabaki ya Browser <a href="#id-3def" id="id-3def"></a>

Mabaki ya browser yanajumuisha aina mbalimbali za data zinazohifadhiwa na browser za wavuti, kama vile historia ya urambazaji, alamisho na data ya akiba. Mabaki haya huhifadhiwa katika folda maalum ndani ya mfumo wa uendeshaji. Mahali na majina ya folda hutofautiana kulingana na browser, lakini kwa ujumla huhifadhi aina zinazofanana za data.

Huu hapa ni muhtasari wa mabaki ya browser yanayotumika sana:

- **Historia ya Urambazaji**: Hufuatilia tovuti ambazo mtumiaji ametembelea, na husaidia kutambua kutembelea tovuti hasidi.
- **Data ya Kukamilisha Kiotomatiki**: Mapendekezo yanayotokana na utafutaji wa mara kwa mara; yakichanganywa na historia ya urambazaji, yanaweza kutoa maarifa.
- **Alamisho**: Tovuti zilizohifadhiwa na mtumiaji ili kuzifikia haraka.
- **Viendelezi na Viongezi**: Viendelezi au viongezi vya browser vilivyosakinishwa na mtumiaji.
- **Akiba**: Huhifadhi maudhui ya wavuti (k.m., picha, faili za JavaScript) ili kuboresha kasi ya upakiaji wa tovuti; ni muhimu kwa uchanganuzi wa forensics.
- **Taarifa za Kuingia**: Taarifa za kuingia zilizohifadhiwa.
- **Favicons**: Ikoni zinazohusishwa na tovuti, zinazoonekana kwenye vichupo na alamisho, na zinazoweza kutoa maelezo ya ziada kuhusu tovuti alizotembelea mtumiaji.
- **Vipindi vya Browser**: Data inayohusiana na vipindi vya browser vilivyo wazi.
- **Vipakuliwa**: Rekodi za faili zilizopakuliwa kupitia browser.
- **Data ya Fomu**: Taarifa zilizoingizwa kwenye fomu za wavuti na kuhifadhiwa ili zitumike kama mapendekezo ya kujaza kiotomatiki baadaye.
- **Picha Ndogo za Muhtasari**: Picha za muhtasari wa tovuti.
- **Custom Dictionary.txt**: Maneno yaliyoongezwa na mtumiaji kwenye kamusi ya browser.

## Firefox

Firefox hupanga data ya mtumiaji ndani ya profiles, zinazohifadhiwa katika maeneo maalum kulingana na mfumo wa uendeshaji:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Faili ya `profiles.ini` ndani ya saraka hizi huorodhesha profiles za mtumiaji. Data ya kila profile huhifadhiwa kwenye folda yenye jina lililo kwenye kigezo cha `Path` ndani ya `profiles.ini`, ambayo iko kwenye saraka hiyo hiyo na `profiles.ini` yenyewe. Ikiwa folda ya profile haipo, huenda ilifutwa.

Ndani ya kila folda ya profile, unaweza kupata faili kadhaa muhimu:<sup>[[1]](#references)</sup>

- **places.sqlite**: Huhifadhi historia, alamisho na vipakuliwa. Zana kama [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kwenye Windows zinaweza kufikia data ya historia.
  - Tumia maswali maalum ya SQL kutoa taarifa za historia na vipakuliwa.
- **bookmarkbackups**: Ina nakala rudufu za alamisho.
- **formhistory.sqlite**: Huhifadhi data ya fomu za wavuti.
- **handlers.json**: Hudhibiti handlers za itifaki.
- **persdict.dat**: Maneno ya kamusi maalum.
- **addons.json** na **extensions.sqlite**: Taarifa kuhusu viongezi na viendelezi vilivyosakinishwa.
- **cookies.sqlite**: Huhifadhi cookies; [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) inaweza kutumika kuzikagua kwenye Windows.
- **cache2/entries** au **startupCache**: Data ya akiba, inayoweza kufikiwa kupitia zana kama [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Huhifadhi favicons.
- **prefs.js**: Mipangilio na mapendeleo ya mtumiaji.
- **downloads.sqlite**: Hifadhidata ya zamani ya vipakuliwa, ambayo sasa imeunganishwa kwenye places.sqlite.
- **thumbnails**: Picha ndogo za muhtasari wa tovuti.
- **logins.json**: Taarifa za kuingia zilizosimbwa kwa njia fiche.
- **key4.db** au **key3.db**: Huhifadhi funguo za usimbaji fiche zinazolinda taarifa nyeti.

Pia, unaweza kuangalia mipangilio ya browser ya kuzuia phishing kwa kutafuta maingizo ya `browser.safebrowsing` kwenye `prefs.js`. Maingizo haya huonyesha ikiwa vipengele vya kuvinjari kwa usalama vimewezeshwa au vimezimwa.<sup>[[2]](#references)</sup>

Ili kusimbua taarifa za kuingia zilizohifadhiwa kutoka kwenye profile unayoweza kufikia, lazima utoe au urejeshe kando [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), ikiwa imewekwa; profile yenyewe haionyeshi nenosiri hilo. Thibitisha kuwa taarifa yoyote ya kuingia iliyorejeshwa inathibitisha utambulisho kwa akaunti yake ya wavuti. Ufikiaji wa root wa Unix unahitaji uthibitisho tofauti kwamba taarifa hizo za kuingia pia zinakubaliwa na uthibitishaji wa Unix kwa root. Unaweza kukagua taarifa za kuingia zilizohifadhiwa kwa kutumia [firefox_decrypt](https://github.com/unode/firefox_decrypt). Mfano ufuatao hujaribu Primary Password zinazowezekana kutoka kwenye faili la nywila:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Browser artifacts - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome huhifadhi profaili za watumiaji katika maeneo maalum kulingana na mfumo wa uendeshaji:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Ndani ya saraka hizi, data nyingi za watumiaji zinaweza kupatikana kwenye folda za **Default/** au **ChromeDefaultData/**. Faili zifuatazo zina data muhimu:<sup>[[1]](#references)</sup>

- **History**: Ina URL, vipakuliwa na maneno muhimu ya utafutaji. Kwenye Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) inaweza kutumika kusoma historia. Safu wima ya "Transition Type" ina maana mbalimbali, zikiwemo kubofya viungo na mtumiaji, kuandika URL, kutuma fomu na kupakia upya kurasa.
- **Cookies**: Huhifadhi cookies. Kwa ukaguzi, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) inapatikana.
- **Cache**: Huhifadhi data iliyo kwenye cache. Watumiaji wa Windows wanaweza kutumia [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) kuikagua.

  Programu za desktop zinazotumia Electron (k.m., Discord) pia hutumia Chromium Simple Cache na huacha artifacts nyingi kwenye diski. Tazama:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Alamisho za mtumiaji.
- **Web Data**: Ina historia ya fomu.
- **Favicons**: Huhifadhi favicon za tovuti.
- **Login Data**: Ina taarifa za kuingia kama majina ya watumiaji na nywila.
- **Current Session**/**Current Tabs**: Data kuhusu kipindi cha sasa cha kuvinjari na tabo zilizo wazi.
- **Last Session**/**Last Tabs**: Taarifa kuhusu tovuti zilizokuwa zimefunguliwa katika kipindi cha mwisho kabla Chrome haijafungwa.
- **Extensions**: Saraka za browser extensions na addons.
- **Thumbnails**: Huhifadhi vijipicha vya tovuti.
- **Preferences**: Faili yenye taarifa nyingi, zikiwemo mipangilio ya plugins, extensions, madirisha ibukizi, arifa na zaidi.
- **Browser’s built-in anti-phishing**: Kuangalia kama ulinzi dhidi ya anti-phishing na malware umewashwa, endesha `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Tafuta `{"enabled: true,"}` kwenye matokeo.<sup>[[2]](#references)</sup>

Saraka ya `Local Extension Settings/<extension-id>/` katika profaili ya Chromium inaweza kuwa na hali ya ndani ya extension, ikiwemo nyenzo muhimu za password manager. Kwa mfano, [Passbolt inasema kuwa private key yake iliyosimbwa huhifadhiwa kwenye local storage ya browser extension](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), na [Chrome extension ID yake](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) hutambua saraka husika. Kuwepo kwa saraka pekee hakuthibitishi kuwa key ipo wala hakufungui vault: mtumiaji lazima awe na ufikiaji wa data ya profaili, private key inayoweza kutumika na passphrase, pamoja na njia iliyoidhinishwa ya kurejesha au kuthibitisha utambulisho kwenye seva. Kipengee cha vault chenye nywila ya akaunti ya mfumo wa uendeshaji kinahitaji uthibitishaji tofauti wa matumizi tena ya akaunti. Uhesabuji wa kawaida unapaswa kuripoti njia ya hifadhi pekee, bila kutoa faili zake za LevelDB au thamani za siri.

## **SQLite DB Data Recovery**

Kama inavyoonekana katika sehemu zilizotangulia, Chrome na Firefox hutumia hifadhidata za **SQLite** kuhifadhi data. Inawezekana **kurejesha maingizo yaliyofutwa kwa kutumia zana** [**sqlparse**](https://github.com/padfoot999/sqlparse) **au** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 husimamia data na metadata zake katika maeneo mbalimbali, jambo linalosaidia kutenganisha taarifa zilizohifadhiwa na maelezo yake ili kurahisisha ufikiaji na usimamizi.

### Hifadhi ya Metadata

Metadata ya Internet Explorer huhifadhiwa kwenye `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (ambapo VX ni V01, V16 au V24). Faili ya `V01.log` iliyoambatanishwa inaweza kuonyesha tofauti za muda wa urekebishaji ikilinganishwa na `WebcacheVX.data`, ikionyesha kuwa huenda ikahitaji kurekebishwa kwa kutumia `esentutl /r V01 /d`. Metadata hii, iliyohifadhiwa kwenye hifadhidata ya ESE, inaweza kurejeshwa na kukaguliwa kwa kutumia zana kama photorec na [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), mtawalia. Ndani ya jedwali la **Containers**, unaweza kubaini majedwali au containers maalum ambamo kila sehemu ya data imehifadhiwa, ikiwemo maelezo ya cache ya zana nyingine za Microsoft kama Skype.

### Ukaguzi wa Cache

Zana ya [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) huruhusu ukaguzi wa cache na inahitaji eneo la folda ambamo data ya cache imetolewa. Metadata ya cache inajumuisha jina la faili, saraka, idadi ya ufikiaji, chanzo cha URL na mihuri ya muda inayoonyesha muda wa kuundwa, kufikiwa, kurekebishwa na kuisha kwa cache.

### Usimamizi wa Cookies

Cookies zinaweza kuchunguzwa kwa kutumia [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), huku metadata ikijumuisha majina, URL, idadi ya ufikiaji na maelezo mbalimbali ya muda. Cookies zinazoendelea huhifadhiwa kwenye `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, huku cookies za kipindi zikikaa kwenye memory.

### Maelezo ya Vipakuliwa

Metadata ya vipakuliwa inaweza kupatikana kupitia [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), huku containers maalum zikiwa na data kama URL, aina ya faili na eneo la upakuaji. Faili halisi zinapatikana kwenye `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historia ya Kuvinjari

Ili kukagua historia ya kuvinjari, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) inaweza kutumika. Inahitaji eneo la faili za historia zilizotolewa na usanidi wa Internet Explorer. Metadata hapa inajumuisha nyakati za urekebishaji na ufikiaji, pamoja na idadi ya ufikiaji. Faili za historia ziko kwenye `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL Zilizoandikwa

URL zilizoandikwa na nyakati za matumizi yake huhifadhiwa kwenye registry chini ya `NTUSER.DAT`, katika `Software\Microsoft\InternetExplorer\TypedURLs` na `Software\Microsoft\InternetExplorer\TypedURLsTime`. Hufuatilia URL 50 za mwisho zilizoingizwa na mtumiaji pamoja na nyakati zilizoingizwa mara ya mwisho.

## Microsoft Edge

Microsoft Edge huhifadhi data ya mtumiaji kwenye `%userprofile%\Appdata\Local\Packages`. Njia za aina mbalimbali za data ni:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Data ya Safari huhifadhiwa kwenye `/Users/$User/Library/Safari`. Faili muhimu ni pamoja na:<sup>[[3]](#references)</sup>

- **History.db**: Ina majedwali ya `history_visits` na `history_items` yenye URL na mihuri ya muda ya kutembelea. Tumia `sqlite3` kuuliza data.
- **Downloads.plist**: Taarifa kuhusu faili zilizopakuliwa.
- **Bookmarks.plist**: Huhifadhi URL zilizowekwa alamisho.
- **TopSites.plist**: Tovuti zilizotembelewa mara nyingi zaidi.
- **Extensions.plist**: Orodha ya Safari browser extensions. Tumia `plutil` au `pluginkit` kuzipata.
- **UserNotificationPermissions.plist**: Vikoa vilivyoruhusiwa kutuma arifa. Tumia `plutil` kuchanganua.
- **LastSession.plist**: Tabo za kipindi kilichopita. Tumia `plutil` kuchanganua.
- **Browser’s built-in anti-phishing**: Kagua kwa kutumia `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Jibu la 1 linaonyesha kuwa kipengele hiki kinatumika.<sup>[[2]](#references)</sup>

## Opera

Data ya Opera iko kwenye `/Users/$USER/Library/Application Support/com.operasoftware.Opera` na hutumia fomati ya Chrome kwa historia na vipakuliwa.

- **Browser’s built-in anti-phishing**: Thibitisha kwa kuangalia kama `fraud_protection_enabled` katika faili la Preferences limewekwa kuwa `true`, kwa kutumia `grep`.<sup>[[2]](#references)</sup>

Njia na amri hizi ni muhimu kwa kufikia na kuelewa data ya kuvinjari iliyohifadhiwa na browser mbalimbali.

## References

- [1] [Uchunguzi wa Kiforensiki wa Web Browsers: Mwongozo wa Kufanya Uchambuzi wa Kiforensiki wa Web Browsers](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Majibu ya Matukio ya macOS | Sehemu ya 3: Udanganyifu wa Mfumo](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Majibu ya Matukio ya OS X: Uandishi wa Scripts na Uchambuzi, na Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
