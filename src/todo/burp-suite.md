# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder-payloadtipes

Burp Intruder bevat die volgende ingeboude payload-opwekkers en -transformasies:<sup>[[1]](#references)</sup>

- **Eenvoudige lys:** Gebruik ’n opgestelde lys stringe as payloads.
- **Lêer tydens uitvoering:** Lees een payload per reël tydens uitvoering. Dit is nuttig vir groot lyste, omdat Burp nie die hele lêer in die geheue laai nie.
- **Letterkasaanpassing:** Genereer die onveranderde waarde, kleinletter- en hooflettervorme, `Propername` (eerste letter hoofletter en die res kleinletters), of `ProperName` (eerste letter hoofletter en die oorblywende karakters onveranderd). Burp verwyder duplikaatresultate.
- **Getalle:** Genereer opeenvolgende of ewekansige getalle binne ’n opgestelde reeks.
- **Brute forcer:** Genereer elke permutasie vir ’n gekose karakterstel en minimum-/maksimumlengte.

## Uitbreidings en aanvullende nutsgoed

- **Collabfiltrator** genereer payloads wat opdragte uitvoer en die uitvoer daarvan deur DNS-navrae na Burp Collaborator eksfiltreer.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** voer Burp-bevindinge uit vir gebruik in ander verslagdoeningswerkvloeie.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** omskep HTTP-versoeke in skrifte in verskeie tale.<sup>[[4]](#references)</sup>

## Magtigingstoetsing met veelvuldige sessies met Session Switcher

[Session Switcher](https://github.com/doyensec/burp-session-switcher) is ’n Java-uitbreiding vir Burp Suite `2025.5+` wat koekies en ongewone opskrifte as benoemde geloofsbrieweprofiele stoor. Wanneer ’n profiel in ’n redigeerbare versoekredigeerder gekies word, insluitend Repeater of ’n onderskepte Proxy-versoek, vervang dit die versoek se verifikasiemateriaal. Dit help met herafspeel en is **nie ’n magtigingsomseiling nie**: gebruik dit om dieselfde versoek as verskillende rekeninge te stuur wanneer jy horisontale toegang, vertikale rolgrense, tenant-isolasie en [IDOR/BOLA](../pentesting-web/idor.md) nagaan as deel van die [webtoetsmetodologie](../pentesting-web/web-vulnerabilities-methodology.md).<sup>[[5]](#references)[[8]](#references)</sup>

### Herhaalbare werkvloei vir identiteitsverskille

Die volgende werkvloei hou die hulpbron/aksie en die identiteit wat optree as afsonderlike toetsveranderlikes, wat vals resultate weens verouderde tokens of die verkeerde blaaiersessie verminder.<sup>[[5]](#references)[[8]](#references)</sup>

1. Meld toetsrekeninge wat elke relevante gebruiker, rol en tenant verteenwoordig aan in afsonderlike blaaierprofiele of -houers.
2. Maak ’n versoek met een identiteit se koekies en opskrifte oop, kies **Sessions > New** en gee die profiel ’n ondubbelsinnige naam soos `tenant-a-user` of `tenant-b-admin`. Herhaal dit vir elke toetsidentiteit.
3. Stuur ’n moontlike versoek na Repeater en speel dit weer af sonder om die metode, eindpunt, parameters of objekidentifiseerder te verander, terwyl jy slegs die gekose sessie wissel. Vergelyk die antwoorddata en waarneembare toestandsveranderinge, nie net statuskodes nie.
4. Speel vir objekvlakkontroles ’n versoek vir ’n objek wat bekend is as behorende aan rekening A weer af terwyl rekening B se profiel gekies is. Speel vir funksievlakkontroles dieselfde bevoorregte aksie weer af met profiele met minder voorregte.
5. Gebruik ná herverifikasie of tokenrotasie **Update** op ’n huidige blaaierversoek, of stel ’n Auto Update-reël op voordat jy die vergelyking herhaal.

### Vaslegging- en inspuitsemantiek

Gaan die opdaterings-/inspuitmodusse na voordat jy toets, want ’n hibriede versoek wat geloofsbriewe van twee identiteite bevat, kan die vergelyking ongeldig maak. Die huidige verstekinstellings weerspieël alle versoekkoekies in ’n profiel, werk slegs reeds gestoorde ongewone opskrifte by, weerspieël die gekose profiel se koekies in die bestemmingsversoek (en verwyder die bestaande koekies daarvan), en voeg die profiel se opskrifte by. Die kieser kan beperk word tot ’n presiese subdomein, die topvlaktoepassingsdomein (verstek), of alle gestoorde profiele.<sup>[[7]](#references)</sup>

- **Mirror** is nuttig wanneer die volledige stel koekies ’n identiteit bepaal en verouderde bestemmingskoekies verwyder moet word.
- **Update existing** volg waardes wat roteer sonder om onverwante koekies of opskrifte uit blaaierverkeer aan te leer.
- **Add all** behou ekstra waardes wat reeds in die profiel of versoek gestoor is; verifieer dat dit nie identiteitsdata van die vorige sessie agterlaat nie.
- **Do nothing** sluit óf koekies óf opskrifte uit profielopdaterings uit wanneer daardie geloofsbrieflokasie nie relevant is nie.

### Sessiesinchronisering via Proxy

Auto Update-reëls koppel Proxy-verkeer aan ’n gestoorde profiel en verfris die profiel se koekies/opskrifte. Verkies ’n stabiele onderskeidende kenmerk, soos ’n toegewyde versoekopskrif, ’n profielspesifieke `User-Agent`-merker, ’n identifiserende koekie, `X-PwnFox-Color` of ’n JWT-eis; kombineer dit met omvang-/domein-/padvoorwaardes sodat onverwante toepassings nie die profiel kan opdateer nie. Alle voorwaardes in een reël word in volgorde as logiese `AND` geëvalueer, dus plaas beperkende kontroles eerste; implementeer `OR` deur veelvuldige reëls te skep wat op dieselfde profiel gerig is. Negatiewe passing word ook ondersteun.<sup>[[6]](#references)</sup>

Kies vir elke passende reël **Mirror request**, **Add all**, **Update existing** of **Do nothing** afsonderlik vir koekies en opskrifte. Slegs-versoekreëls loop wanneer Proxy die versoek ontvang; wanneer ’n antwoordstatus-, antwoordopskrif- of antwoordliggaamvoorwaarde bygevoeg word, word evaluering uitgestel totdat die antwoord arriveer. ’n Uitligkleur kan passende verkeer merk, wat help om te verifieer dat elke blaaieridentiteit slegs sy bedoelde profiel opdateer.<sup>[[6]](#references)</sup>

Gestoorde profiele is in die Burp-projek en JSON-uitvoer van projekdata sluit die sessies, en dus hul koekies en opskrifte, in. Behandel albei lêers as aktiewe geloofsbriewemateriaal, beperk toegang daartoe en vee die gestoorde uitbreidingsdata ná die opdrag uit.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [PortSwigger-dokumentasie - Burp Intruder-payloadtipes](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - Session Switcher-bron- en gebruiksdokumentasie](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - Session Switcher Auto Update-reëls](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - Session Switcher-instellings](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: Vereenvoudiging van magtigingstoetsing met veelvuldige sessies in Burp Suite](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
