# Platformy online z API

{{#include ../banners/hacktricks-training.md}}

Te usługi obsługują procesy reconnaissance, reputation, breach lub enrichment. Ich API, limity, ceny i dozwolone zastosowania często się zmieniają; przed wysłaniem identyfikatorów klientów lub poufnych danych sprawdź aktualną dokumentację dostawcy oraz autoryzację do engagementu.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Sprawdź, czy adres IP był powiązany z podejrzaną lub złośliwą aktywnością. Dostęp może wymagać konta lub klucza API.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Sprawdź, czy adres IP, nazwa użytkownika lub adres e-mail były powiązane z automatyczną rejestracją kont lub inną zgłoszoną aktywnością botów.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Znajduj i weryfikuj profesjonalne adresy e-mail oraz wzorce kontaktów powiązane z domenami. Sprawdź aktualny plan pod kątem limitów żądań i dozwolonych zastosowań.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Wyszukuj wskaźniki threat intelligence i aktywność powiązaną z adresami IP oraz domenami.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Wzbogać adres e-mail, domenę lub firmę o dostępne dane biznesowe/profilowe. Zakres danych, dostęp i ograniczenia dotyczące prywatności zależą od aktualnego produktu i planu.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identyfikuj technologie obserwowane na stronach internetowych i uzyskuj dane historyczne lub informacje o relacjach, jeśli zezwala na to wybrany plan.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Sprawdź, czy adres IP jest powiązany z podejrzaną lub złośliwą aktywnością. Potwierdź aktualne plany API i limity.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Sprawdzaj kategoryzację FortiGuard i threat intelligence dla domen, URL-i lub adresów IP. Dostępność różni się w zależności od usługi.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Sprawdź, czy adres IP znajduje się na liście zgłoszonej aktywności spamowej.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Pobierz reputację domeny na podstawie społeczności usługi i innych sygnałów.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Uzyskaj geolokalizację, ASN, organizację i powiązane metadane adresu IP. Sprawdź aktualny plan pod kątem limitów.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Ta platforma dostarcza informacje o DNS i infrastrukturze, takie jak historyczne rozwiązywanie nazw, domeny powiązane z adresami IP lub serwerami nazw oraz powiązane rekordy. Historyczny DNS może ujawnić wcześniejszy adres origin, ale nie omija niezawodnie CDN i musi zostać zweryfikowany.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Wzbogać adres e-mail, domenę lub nazwę firmy o dostępne atrybuty tożsamości i informacje biznesowe. Przetwarzaj dane osobowe zgodnie z wymaganiami dotyczącymi autoryzacji i prywatności.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

Funkcje PassiveTotal firmy RiskIQ zostały przeniesione do Microsoft Defender Threat Intelligence. Dostęp do produktu, API i zachowane funkcje uległy zmianie, dlatego korzystaj z aktualnej dokumentacji Microsoft zamiast opierać się na założeniach dotyczących starszego PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Wyszukuj domeny, adresy IP, adresy e-mail oraz zindeksowane dane historyczne lub leaked, z uwzględnieniem mechanizmów kontroli dostępu usługi.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Wyszukuj adresy IP i inne wskaźniki w celu uzyskania danych threat intelligence i informacji o reputacji.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Wyszukuj adresy IP lub zakresy pod kątem obserwacji skanowania Internetu i typowej aktywności usług. Sprawdź aktualne warunki wersji próbnej i dostępu społecznościowego.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Pobieraj informacje o skanowaniu Internetu i usługach dla adresu IP, hosta lub zapytania wyszukiwania. Dostęp do API zależy od planu konta.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Wyszukuj dane dotyczące hostów, certyfikatów, domen i usług internetowych; model danych oraz zakres różnią się od Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Wyszukuj według słów kluczowych w indeksie dostawcy zawierającym publicznie obserwowane obiekty i buckety cloud-storage.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Wyszukuj w zindeksowanych danych breach adresy e-mail, nazwy użytkowników, domeny i powiązane rekordy. Korzystaj wyłącznie z autoryzacją i unikaj niepotrzebnego ujawniania danych z breach.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Wyszukuj w zindeksowanej treści paste wystąpienia adresu e-mail lub innego terminu. Przed integracją sprawdź, czy usługa jest nadal dostępna.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Pobieraj sygnały reputacji i ryzyka dla adresu e-mail.

## GhostProject (historyczne) <sup>[[24]](#references)</sup>

Historycznie reklamowano wyszukiwanie leaked danych e-mail/hasło. Traktuj usługę jako obsługę przez zewnętrzny podmiot wysokiego ryzyka i przed użyciem zweryfikuj jej dostępność, legalność oraz autoryzację.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Uzyskaj dane dotyczące skanowania Internetu, ekspozycji i threat intelligence dla adresów IP oraz powiązanych zasobów.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Sprawdź, czy adres e-mail lub zweryfikowana domena występują w znanych breach. Oddzielna usługa Pwned Passwords sprawdza hashe haseł na podstawie prefiksu; **nie** ujawnia haseł w postaci jawnego tekstu.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Pobieraj geolokalizację adresu IP, informacje o data center, ASN, proxy/VPN oraz powiązane pola enrichment. Limity zależą od aktualnego planu.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolokalizacja IP i enrichment ukierunkowany na OSINT z wybranymi punktami danych. Sprawdź aktualne warunki dotyczące zastosowań komercyjnych.


[DNSDumpster](https://dnsdumpster.com/) dostarcza wyniki DNS-reconnaissance.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) dostarcza informacje o witrynach, hostingu i infrastrukturze internetowej.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) dostarcza internetowy interfejs do subdomain-discovery.<sup>[[31]](#references)</sup>

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
- [24] [Badania Cornell — Protokoły sprawdzania przejętych danych uwierzytelniających (obejmuje GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
