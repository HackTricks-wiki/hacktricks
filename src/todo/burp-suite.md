# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Aina za payload za Intruder

Burp Intruder inajumuisha jenereta na mabadiliko yafuatayo ya payload yaliyojengewa ndani:<sup>[[1]](#references)</sup>

- **Simple list:** Tumia orodha iliyosanidiwa ya mifuatano kama payload.
- **Runtime file:** Soma payload moja kwa kila mstari wakati wa utekelezaji. Hii inafaa kwa orodha kubwa kwa sababu Burp haipakii faili nzima kwenye kumbukumbu.
- **Case modification:** Tengeneza thamani isiyobadilishwa, herufi ndogo na kubwa, miundo ya `Propername` (herufi ya kwanza kubwa na nyingine zote ndogo), au `ProperName` (herufi ya kwanza kubwa huku herufi zilizobaki zikibaki bila kubadilika). Burp huondoa matokeo yanayojirudia.
- **Numbers:** Tengeneza nambari zinazofuatana au za nasibu ndani ya masafa yaliyosanidiwa.
- **Brute forcer:** Tengeneza kila mchanganyiko wa herufi kwa seti ya herufi na urefu wa chini/juu uliochaguliwa.

## Extensions na zana saidizi

- **Collabfiltrator** hutengeneza payload zinazotekeleza amri na kutoa matokeo yake kupitia DNS queries kwenda Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** husafirisha matokeo ya Burp ili yatumike katika michakato mingine ya kuripoti.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** hubadilisha HTTP requests kuwa scripts katika lugha kadhaa.<sup>[[4]](#references)</sup>

## Upimaji wa uidhinishaji wa sessions nyingi kwa kutumia Session Switcher

[Session Switcher](https://github.com/doyensec/burp-session-switcher) ni Java extension ya Burp Suite `2025.5+` inayohifadhi cookies na headers zisizo za kawaida kama wasifu wa credentials wenye majina. Kuchagua wasifu katika kihariri cha request kinachoweza kuhaririwa, ikiwemo Repeater au Proxy request iliyokamatwa, hubadilisha taarifa za uthibitishaji za request. Hii husaidia kurudia request, **si njia ya kukwepa uidhinishaji**: itumie kutuma request ileile kama akaunti tofauti unapokagua ufikiaji wa mlalo, mipaka ya majukumu ya wima, utenganisho wa tenant, na [IDOR/BOLA](../pentesting-web/idor.md) kama sehemu ya [mbinu ya upimaji wa wavuti](../pentesting-web/web-vulnerabilities-methodology.md).<sup>[[5]](#references)[[8]](#references)</sup>

### Mchakato unaorudiwa wa kulinganisha utambulisho

Mchakato ufuatao hutenganisha rasilimali/kitendo na utambulisho wa mtumiaji anayetekeleza kitendo kama vigezo tofauti vya majaribio, hivyo kupunguza matokeo yasiyo sahihi yanayosababishwa na tokens zilizopitwa na wakati au session isiyo sahihi ya kivinjari.<sup>[[5]](#references)[[8]](#references)</sup>

1. Thibitisha akaunti za majaribio zinazowakilisha kila mtumiaji, jukumu na tenant husika katika wasifu tofauti wa kivinjari au containers.
2. Fungua request iliyo na cookies na headers za utambulisho mmoja, chagua **Sessions > New**, na upe wasifu jina lisilo na utata kama `tenant-a-user` au `tenant-b-admin`. Rudia kwa kila utambulisho wa majaribio.
3. Tuma request inayochunguzwa kwa Repeater na uirudie bila kubadilisha method, endpoint, parameters, au kitambulisho cha object, huku ukibadilisha session iliyochaguliwa pekee. Linganisha data ya majibu na mabadiliko ya hali yanayoonekana, si status codes pekee.
4. Kwa ukaguzi wa kiwango cha object, rudia request ya object inayojulikana kuwa ya akaunti A huku ukichagua wasifu wa akaunti B. Kwa ukaguzi wa kiwango cha function, rudia kitendo kilekile chenye ruhusa za juu kwa kutumia wasifu wenye ruhusa za chini.
5. Baada ya kuthibitisha upya au kuzungusha token, tumia **Update** kwenye request ya sasa ya kivinjari au sanidi kanuni ya Auto Update kabla ya kurudia ulinganisho.

### Semantiki za kunasa na kuingiza

Kagua hali za kusasisha/kuingiza kabla ya kufanya majaribio, kwa sababu request mseto iliyo na credentials kutoka kwa utambulisho wawili inaweza kufanya ulinganisho usiwe halali. Mipangilio chaguomsingi ya sasa huakisi cookies zote za request kwenye wasifu, husasisha tu headers zisizo za kawaida ambazo tayari zimehifadhiwa, huakisi cookies za wasifu uliochaguliwa kwenye request lengwa (na kuondoa cookies zake zilizopo), na kuongeza headers za wasifu. Kichaguzi kinaweza kuwekwa kwa subdomain mahususi kabisa, domain ya programu ya kiwango cha juu (chaguomsingi), au wasifu wote uliohifadhiwa.<sup>[[7]](#references)</sup>

- **Mirror** inafaa pale ambapo seti kamili ya cookies hutambulisha utambulisho na cookies zilizopitwa na wakati za request lengwa zinapaswa kuondolewa.
- **Update existing** hufuata thamani zinazozungushwa bila kujifunza cookies au headers zisizohusiana kutoka kwenye trafiki ya kivinjari.
- **Add all** huhifadhi thamani za ziada ambazo tayari zimehifadhiwa kwenye wasifu au request; hakikisha kuwa hii haihifadhi data ya utambulisho kutoka kwenye session iliyotangulia.
- **Do nothing** huondoa cookies au headers kwenye masasisho ya wasifu pale ambapo aina hiyo ya credential haina umuhimu.

### Usawazishaji wa session unaotegemea Proxy

Kanuni za Auto Update huhusisha trafiki ya Proxy na wasifu uliohifadhiwa na kusasisha cookies/headers zake. Pendelea kitambulishi thabiti kama request header maalum, alama ya `User-Agent` mahususi kwa wasifu, cookie ya kutambulisha, `X-PwnFox-Color`, au dai la JWT; kisha kiunganishe na masharti ya scope/domain/path ili programu zisizohusiana zisiweze kusasisha wasifu. Masharti yote katika kanuni moja hutathminiwa kama mantiki ya `AND` kwa mpangilio, kwa hiyo weka ukaguzi wenye vikwazo zaidi kwanza; tekeleza `OR` kwa kuunda kanuni nyingi zinazolenga wasifu uleule. Ulinganishaji hasi pia unaungwa mkono.<sup>[[6]](#references)</sup>

Kwa kila kanuni inayolingana, chagua **Mirror request**, **Add all**, **Update existing**, au **Do nothing** kivyake kwa cookies na headers. Kanuni za request pekee hutekelezwa Proxy inapopokea request; kuongeza sharti la hali ya response, response header, au response body huahirisha tathmini hadi response ifike. Rangi ya kuangazia inaweza kuashiria trafiki inayolingana, na kusaidia kuthibitisha kuwa kila utambulisho wa kivinjari unasasisha wasifu wake uliokusudiwa pekee.<sup>[[6]](#references)</sup>

Wasifu uliohifadhiwa hukaa kwenye project ya Burp, na exports za data ya project za JSON hujumuisha sessions na hivyo cookies na headers zake. Chukulia faili zote mbili kama taarifa hai za credentials, zuia ufikiaji wake, na ufute data iliyohifadhiwa ya extension baada ya engagement.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [Nyaraka za PortSwigger - Aina za payload za Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - Nyaraka za chanzo na matumizi ya Session Switcher](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - Kanuni za Auto Update za Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - Mipangilio ya Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: Kurahisisha Upimaji wa Uidhinishaji wa Sessions Nyingi katika Burp Suite](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
