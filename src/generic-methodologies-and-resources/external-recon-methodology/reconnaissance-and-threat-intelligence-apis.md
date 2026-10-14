# Verkennings- en bedreigingsintelligensie-API's

{{#include ../../banners/hacktricks-training.md}}

Hierdie dienste ondersteun verkennings-, reputasie-, breach- of verrykingswerkvloeie. Hul API's, kwotas, pryse en toegelate gebruike verander gereeld; raadpleeg die huidige dokumentasie van die verskaffer en bevestig toestemming vir die opdrag voordat jy kliëntidentifiseerders of sensitiewe data stuur. Sien die [External Recon Methodology](README.md) vir die volgorde vir bate-ontdekking.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Doen navraag of 'n IP-adres met verdagte of kwaadwillige aktiwiteit geassosieer is. Toegang kan 'n rekening of API-sleutel vereis.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Kontroleer of 'n IP-adres, gebruikersnaam of e-posadres met outomatiese rekeningregistrasie of ander gerapporteerde botaktiwiteit geassosieer is.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Vind en verifieer professionele e-posadresse en kontakpatrone wat met domeine verband hou. Gaan die huidige plan na vir versoeklimiete en toegelate gebruike.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Soek bedreigingsintelligensie-aanwysers en aktiwiteit wat met IP-adresse en domeine geassosieer word.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Verryk 'n e-posadres, domein of maatskappy met beskikbare besigheids-/profieldata. Dekking, toegang en privaatheidsbeperkings hang van die huidige produk en plan af.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifiseer tegnologieë wat op webwerwe waargeneem is, en kry historiese data of verhoudingsdata waar die gekose plan dit toelaat.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Kontroleer of 'n IP-adres met verdagte of kwaadwillige aktiwiteit geassosieer word. Bevestig die huidige API-planne en -limiete.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Soek FortiGuard-kategorisering en bedreigingsintelligensie vir domeine, URL's of IP-adresse. Beskikbaarheid verskil per diens.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Kontroleer of 'n IP-adres gelys is vir gerapporteerde strooiposaktiwiteit.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Kry 'n domein se reputasie op grond van die diens se gemeenskap en ander seine.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Kry geoligging-, ASN-, organisasie- en verwante metadata vir 'n IP-adres. Gaan die huidige plan se kwotas na.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Hierdie platform verskaf DNS- en infrastruktuurintelligensie, soos historiese resolusies, domeine wat met IP-adresse of naambedieners geassosieer word, en verwante rekords. Historiese DNS kan 'n vroeëre oorsprongadres onthul, maar omseil nie 'n CDN betroubaar nie en moet bekragtig word.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Verryk 'n e-posadres, domein of maatskappynaam met beskikbare identiteits- en besigheidskenmerke. Hanteer persoonlike data volgens die vereistes vir toestemming en privaatheid.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQ se PassiveTotal-vermoëns is na Microsoft Defender Threat Intelligence oorgedra. Produktoegang, API's en behoue funksionaliteit het verander; gebruik dus Microsoft se huidige dokumentasie eerder as verouderde aannames oor PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Soek domeine, IP-adresse, e-posadresse en geïndekseerde historiese of uitgelekte data, onderhewig aan die diens se toegangsbeheer.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Soek IP-adresse en ander aanwysers vir bedreigingsintelligensie- en reputasiedata.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Soek IP-adresse of reekse vir waarnemings van internetskandering en algemene diensaktiwiteit. Gaan die huidige proef- en gemeenskapstoegangsvoorwaardes na.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Kry inligting oor internetskanderings en dienste vir 'n IP-adres, gasheer of soeknavraag. API-toegang hang van die rekeningplan af.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Soek gasheer-, sertifikaat-, domein- en internetdiensdatastelle; die datamodel en dekking verskil van Shodan s'n.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Soek die verskaffer se indeks van publiek waargenome wolkbergingsvoorwerpe en buckets volgens sleutelwoord.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Soek geïndekseerde breach-data vir e-posadresse, gebruikersname, domeine en verwante rekords. Gebruik dit slegs met toestemming en vermy onnodige blootstelling aan breach-data.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Soek geïndekseerde paste-inhoud vir voorkomste van 'n e-posadres of ander term. Verifieer dat die diens steeds beskikbaar is voordat jy dit integreer.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Kry reputasie- en risikoseine vir 'n e-posadres.

## GhostProject (historical) <sup>[[24]](#references)</sup>

Het histories soektogte in uitgelekte e-pos-/wagwoorddata geadverteer. Beskou die diens as 'n derdeparty-diens met hoë risiko vir dataverwerking en verifieer die beskikbaarheid, wettigheid en toestemming voordat jy dit gebruik.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Kry data oor internetskanderings, blootstelling en bedreigingsintelligensie vir IP-adresse en verwante bates.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Kontroleer of 'n e-posadres of geverifieerde domein in bekende breaches voorkom. Die aparte Pwned Passwords-diens kontroleer wagwoord-hashes volgens voorvoegsel; dit **onthul nie** gewone tekswagwoorde nie.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Kry IP-geoligging, datasentrum-, ASN-, proxy/VPN- en verwante verrykingsvelde. Kwotas hang van die huidige plan af.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
IP-geoligging en OSINT-gerigte verryking met geselekteerde datapunte. Gaan die huidige voorwaardes vir kommersiële gebruik na.


[DNSDumpster](https://dnsdumpster.com/) verskaf DNS-verkenningsresultate.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) verskaf intelligensie oor webwerwe, huisvesting en internetinfrastruktuur.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) verskaf 'n aanlyn koppelvlak vir subdomein-ontdekking.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [BotScout API](https://botscout.com/api.htm)
- [3] [Hunter API](https://hunter.io/api-documentation)
- [4] [AlienVault OTX API](https://otx.alienvault.com/api)
- [5] [Clearbit](https://dashboard.clearbit.com/)
- [6] [BuiltWith](https://builtwith.com/)
- [7] [FraudGuard](https://fraudguard.io/)
- [8] [FortiGuard Labs](https://www.fortiguard.com/)
- [9] [SpamCop](https://www.spamcop.net/)
- [10] [Web of Trust](https://www.mywot.com/)
- [11] [IPinfo](https://ipinfo.io/)
- [12] [SecurityTrails](https://securitytrails.com/)
- [13] [FullContact](https://www.fullcontact.com/)
- [14] [Microsoft Defender Threat Intelligence](https://learn.microsoft.com/en-us/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti)
- [15] [Intelligence X](https://intelx.io/)
- [16] [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
- [17] [GreyNoise](https://www.greynoise.io/)
- [18] [Shodan](https://www.shodan.io/)
- [19] [Censys](https://censys.com/)
- [20] [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
- [21] [DeHashed](https://www.dehashed.com/)
- [22] [psbdmp](https://psbdmp.ws/)
- [23] [EmailRep](https://emailrep.io/)
- [24] [Cornell-navorsing — Protokolle vir die kontrolering van gekompromitteerde aanmeldbewyse (sluit GhostProject in)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
