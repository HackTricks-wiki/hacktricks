# Izviđanje i API-ji za obaveštajne podatke o pretnjama

{{#include ../../banners/hacktricks-training.md}}

Ove usluge podržavaju izviđanje, proveru reputacije, breach i enrichment procese. Njihovi API-ji, kvote, cene i dozvoljene upotrebe često se menjaju; pre slanja identifikatora korisnika ili osetljivih podataka proverite aktuelnu dokumentaciju dobavljača i ovlašćenje za angažman. Za redosled otkrivanja resursa pogledajte [External Recon Methodology](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Proverite da li je IP adresa povezana sa sumnjivom ili zlonamernom aktivnošću. Za pristup može biti potreban nalog ili API ključ.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Proverite da li su IP adresa, korisničko ime ili adresa e-pošte povezani sa automatizovanom registracijom naloga ili drugim prijavljenim bot aktivnostima.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Pronađite i verifikujte poslovne adrese e-pošte i obrasce kontakata povezane sa domenima. Proverite trenutni plan za ograničenja zahteva i dozvoljene upotrebe.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Pretražite indikatore threat intelligence podataka i aktivnosti povezane sa IP adresama i domenima.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Obogatite adresu e-pošte, domen ili kompaniju dostupnim poslovnim/profilnim podacima. Pokrivenost, pristup i ograničenja privatnosti zavise od trenutnog proizvoda i plana.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifikujte tehnologije uočene na veb-sajtovima i pribavite istorijske podatke ili podatke o povezanim resursima, ako to odabrani plan omogućava.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Proverite da li je IP adresa povezana sa sumnjivom ili zlonamernom aktivnošću. Proverite aktuelne API planove i ograničenja.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Proverite FortiGuard kategorizaciju i threat intelligence podatke za domene, URL-ove ili IP adrese. Dostupnost se razlikuje od usluge do usluge.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Proverite da li je IP adresa na listi zbog prijavljene spam aktivnosti.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Pribavite reputaciju domena zasnovanu na zajednici korisnika usluge i drugim signalima.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Pribavite geolokaciju, ASN, organizaciju i povezane metapodatke za IP adresu. Proverite kvote trenutnog plana.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Ova platforma pruža DNS i obaveštajne podatke o infrastrukturi, kao što su istorijska razrešavanja, domeni povezani sa IP adresama ili name serverima i povezani zapisi. Istorijski DNS može otkriti raniju origin adresu, ali ne zaobilazi pouzdano CDN i potrebno ga je proveriti.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Obogatite adresu e-pošte, domen ili naziv kompanije dostupnim identitetskim i poslovnim atributima. Ličnim podacima rukujte u skladu sa zahtevima za ovlašćenje i privatnost.

## RiskIQ / Microsoft Defender Threat Intelligence (nasleđeni proizvod u tranziciji) <sup>[[14]](#references)</sup>

RiskIQ PassiveTotal mogućnosti prešle su u Microsoft Defender Threat Intelligence. Pristup proizvodu, API-ji i zadržane funkcionalnosti su se promenili, zato koristite aktuelnu Microsoft dokumentaciju, a ne pretpostavke zasnovane na starom PassiveTotal-u.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Pretražite domene, IP adrese, adrese e-pošte i indeksirane istorijske podatke ili leak podatke, u skladu sa kontrolama pristupa usluge.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Pretražite IP adrese i druge indikatore radi pribavljanja threat intelligence podataka i podataka o reputaciji.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Pretražite IP adrese ili opsege da biste pronašli zabeležena internet skeniranja i uobičajene aktivnosti servisa. Proverite aktuelne uslove probnog i besplatnog pristupa za zajednicu.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Pribavite podatke o internet skeniranjima i servisima za IP adresu, host ili upit za pretragu. API pristup zavisi od plana naloga.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Pretražite skupove podataka o hostovima, sertifikatima, domenima i internet servisima; njegov model podataka i pokrivenost razlikuju se od Shodan-ovih.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Pretražite indeks javno uočenih objekata i bucket-a u cloud skladištima ovog dobavljača po ključnoj reči.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Pretražite indeksirane breach podatke po adresama e-pošte, korisničkim imenima, domenima i povezanim zapisima. Koristite samo uz ovlašćenje i izbegavajte nepotrebno izlaganje breach podataka.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Pretražite indeksirani sadržaj paste-ova da biste pronašli pojavljivanje adrese e-pošte ili drugog pojma. Pre integracije proverite da li je usluga i dalje dostupna.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Pribavite signale reputacije i rizika za adresu e-pošte.

## GhostProject (istorijski) <sup>[[24]](#references)</sup>

Istorijski je oglašavao pretrage leak podataka o adresama e-pošte/lozinkama. Smatrajte ovu uslugu visokorizičnom uslugom treće strane i pre upotrebe proverite njenu dostupnost, zakonitost i ovlašćenje.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Pribavite podatke o internet skeniranjima, izloženosti i threat intelligence podatke za IP adrese i povezane resurse.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Proverite da li se adresa e-pošte ili verifikovani domen pojavljuje u poznatim breach-ovima. Zasebna usluga Pwned Passwords proverava hash-eve lozinki po prefiksu; ona **ne** otkriva lozinke u otvorenom tekstu.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Pribavite geolokaciju IP adrese, podatke o data centru, ASN-u, proxy/VPN-u i povezana polja za enrichment. Kvote zavise od aktuelnog plana.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolokacija IP adrese i enrichment za OSINT, sa odabranim podacima. Proverite aktuelne uslove za komercijalnu upotrebu.


[DNSDumpster](https://dnsdumpster.com/) pruža rezultate DNS izviđanja.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) pruža obaveštajne podatke o sajtovima, hostingu i internet infrastrukturi.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) pruža onlajn interfejs za otkrivanje poddomena.<sup>[[31]](#references)</sup>

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
- [24] [Istraživanje Cornell — Protokoli za proveru kompromitovanih akreditiva (uključuje GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
