# Verkenning- en bedreigingsintelligensie-API's

{{#include ../../banners/hacktricks-training.md}}

Hierdie dienste ondersteun verkennings-, reputasie-, breach- of verrykingswerkvloei. Hul API's, kwotas, pryse en toegelate gebruike verander gereeld; bevestig die huidige verskafferdokumentasie en magtiging vir die opdrag voordat jy kliëntidentifiseerders of sensitiewe data stuur. Sien die [Eksterne verkenningsmetodologie](README.md) vir die volgorde van bate-ontdekking.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Doen navraag of 'n IP-adres met verdagte of kwaadwillige aktiwiteit geassosieer is. Toegang kan 'n rekening of API-sleutel vereis.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Kyk of 'n IP-adres, gebruikersnaam of e-posadres met outomatiese rekeningregistrasie of ander gerapporteerde bot-aktiwiteit geassosieer is.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Vind en verifieer professionele e-posadresse en domeinverwante kontakpatrone. Gaan die huidige plan na vir versoeklimiete en toegelate gebruike.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Soek bedreigingsintelligensie-aanwysers en aktiwiteit wat met IP-adresse en domeine geassosieer word.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Verryk 'n e-posadres, domein of maatskappy met beskikbare besigheids-/profieldata. Dekking, toegang en privaatheidsbeperkings hang af van die huidige produk en plan.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifiseer tegnologieë wat op webwerwe waargeneem is en verkry historiese of verwantskapdata waar die gekose plan dit toelaat.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Kyk of 'n IP-adres met verdagte of kwaadwillige aktiwiteit geassosieer word. Bevestig die huidige API-planne en -limiete.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Soek FortiGuard-kategorisering en bedreigingsintelligensie vir domeine, URL's of IP-adresse op. Beskikbaarheid verskil per diens.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Kyk of 'n IP-adres gelys is vir gerapporteerde strooiposaktiwiteit.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Haal 'n domein se reputasie op, gebaseer op die diens se gemeenskap en ander seine.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Verkry geoligging, ASN, organisasie en verwante metadata vir 'n IP-adres. Gaan die huidige plan na vir kwotas.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Hierdie platform verskaf DNS- en infrastruktuurintelligensie, soos historiese resolusies, domeine wat met IP's of naam-bedieners geassosieer word, en verwante rekords. Historiese DNS kan 'n vroeëre oorsprongadres openbaar, maar omseil nie betroubaar 'n CDN nie en moet bekragtig word.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Verryk 'n e-posadres, domein of maatskappynaam met beskikbare identiteits- en besigheidskenmerke. Hanteer persoonlike data volgens magtigings- en privaatheidsvereistes.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQ se PassiveTotal-vermoëns is na Microsoft Defender Threat Intelligence oorgeplaas. Produktoegang, API's en behoue funksionaliteit het verander; gebruik dus Microsoft se huidige dokumentasie eerder as aannames oor die verouderde PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Soek domeine, IP-adresse, e-posadresse en geïndekseerde historiese of uitgelekte data, onderhewig aan die diens se toegangsbeheer.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Soek IP-adresse en ander aanwysers vir bedreigingsintelligensie- en reputasiedata.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Soek IP-adresse of -reekse vir waarnemings van internetskandering en algemene diensaktiwiteit. Gaan die huidige proef- en gemeenskapstoegangsbepalings na.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Haal internetskandering- en diensinligting vir 'n IP-adres, gasheer of soeknavraag op. API-toegang hang af van die rekeningplan.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Soek in datastelle oor gashere, sertifikate, domeine en internetdienste; die datamodel en dekking daarvan verskil van Shodan s'n.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Soek die verskaffer se indeks van openbaar waargenome wolkbergingsobjekte en buckets volgens sleutelwoord.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Soek geïndekseerde breach-data vir e-posadresse, gebruikersname, domeine en verwante rekords. Gebruik dit slegs met magtiging en vermy onnodige blootstelling aan breach-data.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Soek geïndekseerde paste-inhoud vir voorkomste van 'n e-posadres of ander term. Verifieer dat die diens steeds beskikbaar is voordat jy dit integreer.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Haal reputasie- en risikoseine vir 'n e-posadres op.

## GhostProject (histories) <sup>[[24]](#references)</sup>

Het histories soektogte in uitgelekte e-pos-/wagwoorddata geadverteer. Behandel die diens as 'n hoërisiko-derdepartyhanteringsdiens en verifieer die beskikbaarheid, wettigheid en magtiging daarvan voordat jy dit gebruik.

## BinaryEdge (gestaak) <sup>[[25]](#references)</sup>

Het internetskandering-, blootstellings- en bedreigingsintelligensiedata vir IP-adresse en verwante bates aangebied. Die webwerf herlei nou na 'n Coalition-oorgangkennisgewing en die API weier versoeke; behandel dit dus as onbeskikbaar.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Kyk of 'n e-posadres of geverifieerde domein in bekende breaches voorkom. Die afsonderlike Pwned Passwords-diens kontroleer wagwoord-hashes volgens voorvoegsel; dit openbaar **nie** gewone teks-wagwoorde nie.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Haal IP-geoligging, datasentrum-, ASN-, proxy/VPN- en verwante verrykingsvelde op. Kwotas hang af van die huidige plan.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
IP-geoligging en OSINT-georiënteerde verryking met geselekteerde datapunte. Gaan die huidige bepalings vir kommersiële gebruik na.

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
Soek 'n domein op (registrateur, registrasie- en vervaldatums, naam-bedieners, gasheer-IP en land) of 'n IP-adres (die ander domeine wat daarop gehuisves word), en kyk of 'n domein of IP op sy gratis lyste van gekompromitteerde entiteite voorkom: uitvissing- en sinkholed malware-domeine, en adresse wat sy honeypot-sensors in die afgelope 48 uur aangeval het. Die websoektogte en die API vir kompromitteringskontroles vereis nie 'n rekening nie; API-toegang tot die soektogte vereis 'n betaalde plan.


[DNSDumpster](https://dnsdumpster.com/) verskaf DNS-verkenningsresultate.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) verskaf intelligensie oor webwerwe, hosting en internetinfrastruktuur.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) verskaf 'n aanlyn-koppelvlak vir subdomeinontdekking.<sup>[[31]](#references)</sup>

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
- [24] [Cornell-navorsing — Protokolle vir die Kontrolering van Gekompromitteerde Geloofsbriewe (sluit GhostProject in)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper-subdomeinsoeker](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [NetAPI API-dokumentasie](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
