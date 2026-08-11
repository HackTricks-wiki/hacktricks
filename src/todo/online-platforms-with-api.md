# Online Platforme sa API-jem

{{#include ../banners/hacktricks-training.md}}

Ove usluge podržavaju procese izviđanja, procene reputacije, provere breach podataka ili obogaćivanja podataka. Njihovi API-ji, kvote, cene i dozvoljene namene često se menjaju; proverite aktuelnu dokumentaciju vendora i autorizaciju angažmana pre slanja identifikatora korisnika ili osetljivih podataka.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Proverite da li je IP adresa bila povezana sa sumnjivom ili zlonamernom aktivnošću. Pristup može zahtevati nalog ili API ključ.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Proverite da li su IP adresa, korisničko ime ili email adresa bili povezani sa automatskom registracijom naloga ili drugom prijavljenom bot aktivnošću.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Pronađite i verifikujte profesionalne email adrese i obrasce kontakata povezane sa domenom. Proverite trenutni plan za ograničenja zahteva i dozvoljene namene.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Pretražite indikatore threat intelligence-a i aktivnosti povezane sa IP adresama i domenima.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Obogatite email adresu, domen ili kompaniju dostupnim poslovnim/profilnim podacima. Pokrivenost, pristup i ograničenja privatnosti zavise od trenutnog proizvoda i plana.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifikujte tehnologije uočene na sajtovima i pribavite istorijske podatke ili podatke o povezanosti tamo gde ih izabrani plan dozvoljava.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Proverite da li je IP adresa povezana sa sumnjivom ili zlonamernom aktivnošću. Potvrdite aktuelne API planove i ograničenja.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Proverite FortiGuard kategorizaciju i threat intelligence za domene, URL-ove ili IP adrese. Dostupnost se razlikuje u zavisnosti od usluge.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Proverite da li je IP adresa navedena zbog prijavljene spam aktivnosti.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Preuzmite reputaciju domena na osnovu zajednice korisnika usluge i drugih signala.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Dobijte geolokaciju, ASN, organizaciju i povezane metapodatke za IP adresu. Proverite trenutni plan za kvote.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Ova platforma pruža DNS i infrastrukturni intelligence, kao što su istorijska razrešenja, domeni povezani sa IP adresama ili name serverima i povezani zapisi. Istorijski DNS može otkriti raniju origin adresu, ali ne zaobilazi pouzdano CDN i mora biti validiran.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Obogatite email adresu, domen ili naziv kompanije dostupnim identitetskim i poslovnim atributima. Postupajte sa ličnim podacima u skladu sa zahtevima autorizacije i privatnosti.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQ PassiveTotal mogućnosti prešle su u Microsoft Defender Threat Intelligence. Pristup proizvodu, API-ji i zadržane funkcionalnosti su promenjeni, zato koristite aktuelnu Microsoft dokumentaciju umesto pretpostavki zasnovanih na legacy PassiveTotal-u.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Pretražite domene, IP adrese, email adrese i indeksirane istorijske ili leaked podatke, u skladu sa kontrolama pristupa usluge.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Pretražite IP adrese i druge indikatore radi threat intelligence podataka i podataka o reputaciji.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Pretražite IP adrese ili opsege radi uvida u internet skeniranje i uobičajene aktivnosti servisa. Proverite trenutne uslove za trial i community pristup.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Preuzmite informacije o internet skeniranju i servisima za IP adresu, host ili upit za pretragu. API pristup zavisi od plana naloga.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Pretražujte skupove podataka o hostovima, sertifikatima, domenima i internet servisima; njegov model podataka i pokrivenost razlikuju se od Shodan-ovih.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Pretražite indeks provajdera sa javno uočenim cloud-storage objektima i bucketima prema ključnoj reči.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Pretražite indeksirane breach podatke za email adrese, korisnička imena, domene i povezane zapise. Koristite samo uz autorizaciju i izbegavajte nepotrebno izlaganje breach podataka.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Pretražite indeksirani paste sadržaj radi pojavljivanja email adrese ili drugog termina. Proverite da li je usluga još dostupna pre integracije.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Preuzmite signale reputacije i rizika za email adresu.

## GhostProject (historical) <sup>[[24]](#references)</sup>

Istorijski je oglašavao pretrage leaked email/password podataka. Tretirajte uslugu kao visokorizično rukovanje podacima od strane treće strane i proverite njenu dostupnost, zakonitost i autorizaciju pre upotrebe.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Dobijte podatke o internet skeniranju, izloženosti i threat intelligence-u za IP adrese i povezane resurse.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Proverite da li se email adresa ili verifikovani domen pojavljuju u poznatim breach-ovima. Zasebna usluga Pwned Passwords proverava hash-eve lozinki prema prefiksu; ona **ne** otkriva lozinke u otvorenom tekstu.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Preuzmite geolokaciju IP adrese, podatke o data centru, ASN-u, proxy/VPN-u i povezana polja za obogaćivanje podataka. Kvote zavise od trenutnog plana.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolokacija IP adrese i OSINT-orijentisano obogaćivanje podataka sa odabranim tačkama podataka. Proverite aktuelne uslove za komercijalnu upotrebu.


[DNSDumpster](https://dnsdumpster.com/) pruža rezultate DNS izviđanja.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) pruža intelligence o sajtovima, hostingu i internet infrastrukturi.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) pruža online interfejs za otkrivanje poddomena.<sup>[[31]](#references)</sup>

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
- [24] [Cornell istraživanje — Protokoli za proveru kompromitovanih akreditiva (uključuje GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
