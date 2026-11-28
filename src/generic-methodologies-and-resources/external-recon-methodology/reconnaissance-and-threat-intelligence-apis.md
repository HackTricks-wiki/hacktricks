# API-ji za izviđanje i obaveštajne podatke o pretnjama

{{#include ../../banners/hacktricks-training.md}}

Ove usluge podržavaju procese izviđanja, provere reputacije, provera curenja podataka ili obogaćivanja podataka. Njihovi API-ji, kvote, cene i dozvoljena upotreba često se menjaju; pre slanja identifikatora klijenata ili osetljivih podataka proverite aktuelnu dokumentaciju dobavljača i ovlašćenje za angažman. Za redosled otkrivanja sredstava pogledajte [External Recon Methodology](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Proverite da li je IP adresa povezana sa sumnjivom ili zlonamernom aktivnošću. Za pristup može biti potreban nalog ili API ključ.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Proverite da li je IP adresa, korisničko ime ili adresa e-pošte povezana sa automatizovanom registracijom naloga ili drugim prijavljenim aktivnostima botova.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Pronađite i proverite profesionalne adrese e-pošte i obrasce kontakata povezane sa domenom. Proverite ograničenja zahteva i dozvoljenu upotrebu za aktuelni paket.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Pretražite indikatore obaveštajnih podataka o pretnjama i aktivnosti povezane sa IP adresama i domenima.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Obogatite adresu e-pošte, domen ili kompaniju dostupnim poslovnim podacima ili podacima o profilu. Dostupnost podataka, pristup i ograničenja privatnosti zavise od aktuelnog proizvoda i paketa.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifikujte tehnologije uočene na veb-sajtovima i pribavite istorijske podatke ili podatke o povezanosti, u skladu sa odabranim paketom.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Proverite da li je IP adresa povezana sa sumnjivom ili zlonamernom aktivnošću. Proverite aktuelne API pakete i ograničenja.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Potražite FortiGuard kategorizaciju i obaveštajne podatke o pretnjama za domene, URL-ove ili IP adrese. Dostupnost se razlikuje u zavisnosti od usluge.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Proverite da li je IP adresa na listi zbog prijavljene spam aktivnosti.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Pribavite reputaciju domena na osnovu zajednice ove usluge i drugih signala.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Pribavite geolokacijske podatke, ASN, organizaciju i povezane metapodatke za IP adresu. Proverite kvote za aktuelni paket.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Ova platforma pruža DNS i obaveštajne podatke o infrastrukturi, kao što su istorijska razrešavanja, domeni povezani sa IP adresama ili name serverima i povezani zapisi. Istorijski DNS može otkriti raniju origin adresu, ali ne zaobilazi pouzdano CDN i potrebno ga je proveriti.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Obogatite adresu e-pošte, domen ili naziv kompanije dostupnim identitetskim i poslovnim atributima. Ličnim podacima rukujte u skladu sa ovlašćenjima i zahtevima privatnosti.

## RiskIQ / Microsoft Defender Threat Intelligence (prelazak sa starije usluge) <sup>[[14]](#references)</sup>

Mogućnosti RiskIQ PassiveTotal prešle su u Microsoft Defender Threat Intelligence. Pristup proizvodu, API-ji i zadržane funkcionalnosti su se promenili, zato koristite aktuelnu Microsoft dokumentaciju umesto da se oslanjate na pretpostavke o starom PassiveTotal-u.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Pretražujte domene, IP adrese, adrese e-pošte i indeksirane istorijske podatke ili podatke iz leak-ova, u skladu sa kontrolama pristupa ove usluge.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Pretražujte IP adrese i druge indikatore radi pribavljanja obaveštajnih podataka o pretnjama i reputaciji.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Pretražujte IP adrese ili opsege u potrazi za zapažanjima skeniranja interneta i uobičajenih aktivnosti servisa. Proverite aktuelne uslove probnog i besplatnog pristupa za zajednicu.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Pribavite podatke o skeniranju interneta i servisima za IP adresu, host ili upit za pretragu. Pristup API-ju zavisi od paketa naloga.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Pretražujte skupove podataka o hostovima, sertifikatima, domenima i internet servisima; njegov model podataka i pokrivenost razlikuju se od Shodan-ovih.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Pretražujte indeks javno uočenih objekata i bucket-a u cloud skladištima ovog pružaoca usluge pomoću ključne reči.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Pretražujte indeksirane podatke iz leak-ova po adresama e-pošte, korisničkim imenima, domenima i povezanim zapisima. Koristite samo uz ovlašćenje i izbegavajte nepotrebno izlaganje podataka iz leak-ova.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Pretražujte indeksirani sadržaj sa paste sajtova po adresi e-pošte ili drugom terminu. Pre integracije proverite da li je usluga i dalje dostupna.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Pribavite signale o reputaciji i riziku za adresu e-pošte.

## GhostProject (istorijski) <sup>[[24]](#references)</sup>

Istorijski je nudio pretrage podataka o e-pošti/lozinkama iz leak-ova. Smatrajte ovu uslugu visokorizičnom za rukovanje podacima treće strane i pre upotrebe proverite njenu dostupnost, zakonitost i ovlašćenje.

## BinaryEdge (obustavljen) <sup>[[25]](#references)</sup>

Nudio je podatke o skeniranju interneta, izloženosti i obaveštajne podatke o pretnjama za IP adrese i povezana sredstva. Njegov sajt sada preusmerava na obaveštenje o prelasku na Coalition, a API odbija zahteve, zato smatrajte uslugu nedostupnom.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Proverite da li se adresa e-pošte ili verifikovani domen pojavljuju u poznatim leak-ovima. Zasebna usluga Pwned Passwords proverava hash-eve lozinki pomoću prefiksa; ona **ne** otkriva lozinke u otvorenom tekstu.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Pribavite geolokaciju IP adrese, podatke o data-centru, ASN-u, proxy/VPN-u i povezana polja za obogaćivanje podataka. Kvote zavise od aktuelnog paketa.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolokacija IP adresa i obogaćivanje podataka usmereno na OSINT, uz odabrane podatke. Proverite aktuelne uslove za komercijalnu upotrebu.

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
Pretražite domen (registrar, datume registracije i isteka, name servere, IP adresu hostinga i državu) ili IP adresu (ostale domene koji se na njoj hostuju) i proverite da li se domen ili IP adresa nalaze na njihovim besplatnim listama kompromitovanih resursa: phishing i sinkhole domeni sa malverom, kao i adrese koje su napale njihove honeypot senzore u poslednjih 48 sati. Za pretrage na veb-sajtu i API za proveru kompromitovanih resursa nije potreban nalog; za pristup API-ju za pretrage potreban je plaćeni paket.


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
- [24] [Cornell research — Protokoli za proveru kompromitovanih akreditiva (uključuje GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [NetAPI API dokumentacija](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
