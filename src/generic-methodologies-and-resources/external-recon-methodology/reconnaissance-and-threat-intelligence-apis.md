# Rozpoznanie i API wywiadu o zagrożeniach

{{#include ../../banners/hacktricks-training.md}}

Usługi te wspierają procesy rozpoznania, oceny reputacji, wyszukiwania naruszeń danych lub wzbogacania informacji. Ich API, limity, ceny i dozwolone zastosowania często się zmieniają; przed przesłaniem identyfikatorów klientów lub poufnych danych sprawdź aktualną dokumentację dostawcy i upewnij się, że masz zgodę na działania w ramach zlecenia. Sekwencję wykrywania zasobów opisano w [metodyce zewnętrznego rozpoznania](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Sprawdź, czy adres IP był powiązany z podejrzaną lub złośliwą aktywnością. Dostęp może wymagać konta lub klucza API.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Sprawdź, czy adres IP, nazwa użytkownika lub adres e-mail były powiązane z automatycznym rejestrowaniem kont lub inną zgłoszoną aktywnością botów.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Znajduj i weryfikuj służbowe adresy e-mail oraz wzorce kontaktowe powiązane z domenami. Sprawdź aktualny plan pod kątem limitów żądań i dozwolonych zastosowań.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Wyszukuj wskaźniki wywiadu o zagrożeniach i aktywność powiązaną z adresami IP oraz domenami.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Wzbogać adres e-mail, domenę lub nazwę firmy o dostępne dane biznesowe i profilowe. Zakres danych, dostęp i ograniczenia dotyczące prywatności zależą od aktualnego produktu i planu.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identyfikuj technologie zaobserwowane na stronach internetowych i uzyskuj dane historyczne lub informacje o powiązaniach, jeśli pozwala na to wybrany plan.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Sprawdź, czy adres IP jest powiązany z podejrzaną lub złośliwą aktywnością. Potwierdź aktualne plany API i limity.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Sprawdź kategoryzację FortiGuard i informacje o zagrożeniach dla domen, URL-i lub adresów IP. Dostępność zależy od usługi.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Sprawdź, czy adres IP znajduje się na liście adresów zgłoszonych jako źródła spamu.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Pobierz ocenę reputacji domeny na podstawie społeczności usługi i innych sygnałów.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Uzyskaj geolokalizację, ASN, informacje o organizacji i powiązane metadane dla adresu IP. Sprawdź aktualny plan pod kątem limitów.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Platforma dostarcza informacje o DNS i infrastrukturze, takie jak historyczne rozpoznania, domeny powiązane z adresami IP lub serwerami nazw oraz powiązane rekordy. Historyczne dane DNS mogą ujawnić wcześniejszy adres źródłowy, ale nie pozwalają niezawodnie ominąć CDN i wymagają weryfikacji.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Wzbogać adres e-mail, domenę lub nazwę firmy o dostępne atrybuty tożsamości i informacje biznesowe. Przetwarzaj dane osobowe zgodnie z wymogami dotyczącymi upoważnienia i prywatności.

## RiskIQ / Microsoft Defender Threat Intelligence (przejście ze starszej usługi) <sup>[[14]](#references)</sup>

Funkcje RiskIQ PassiveTotal zostały przeniesione do Microsoft Defender Threat Intelligence. Dostęp do produktu, API i zachowane funkcje uległy zmianie, dlatego korzystaj z aktualnej dokumentacji Microsoftu, a nie z założeń dotyczących starszej usługi PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Wyszukuj domeny, adresy IP, adresy e-mail oraz zindeksowane dane historyczne lub leaked — z uwzględnieniem mechanizmów kontroli dostępu usługi.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Wyszukuj adresy IP i inne wskaźniki, aby uzyskać informacje o wywiadzie o zagrożeniach i reputacji.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Wyszukuj adresy IP lub zakresy, aby sprawdzić obserwacje skanowania Internetu i typowej aktywności usług. Sprawdź aktualne warunki wersji próbnej i dostępu społecznościowego.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Pobieraj informacje o skanach Internetu i usługach dla adresu IP, hosta lub zapytania wyszukiwania. Dostęp do API zależy od planu konta.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Przeszukuj zbiory danych hostów, certyfikatów, domen i usług internetowych; model danych i zakres różnią się od tych w Shodan.

## [Wyszukiwanie bucketów GrayHatWarfare](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Wyszukuj według słów kluczowych w indeksie dostawcy obejmującym publicznie zaobserwowane obiekty i buckety w chmurze.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Przeszukuj zindeksowane dane z naruszeń pod kątem adresów e-mail, nazw użytkowników, domen i powiązanych rekordów. Korzystaj z usługi wyłącznie za zgodą i unikaj niepotrzebnego ujawniania danych z naruszeń.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Przeszukuj zindeksowaną zawartość serwisów paste pod kątem wystąpień adresu e-mail lub innego terminu. Przed integracją sprawdź, czy usługa jest nadal dostępna.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Pobierz sygnały reputacji i ryzyka dla adresu e-mail.

## GhostProject (usługa historyczna) <sup>[[24]](#references)</sup>

Historycznie oferował wyszukiwanie w danych leaked zawierających adresy e-mail i hasła. Traktuj tę usługę jako wiążącą się z wysokim ryzykiem obsługi danych przez podmiot zewnętrzny i przed użyciem sprawdź jej dostępność, legalność oraz wymagane upoważnienie.

## BinaryEdge (usługa wycofana) <sup>[[25]](#references)</sup>

Oferował dane o skanach Internetu, ekspozycji i wywiadzie o zagrożeniach dla adresów IP oraz powiązanych zasobów. Jego strona przekierowuje obecnie do komunikatu Coalition o przejściu na inną usługę, a API odrzuca żądania, dlatego należy uznać go za niedostępny.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Sprawdź, czy adres e-mail lub zweryfikowana domena pojawiają się w znanych naruszeniach. Oddzielna usługa Pwned Passwords sprawdza skróty haseł na podstawie prefiksu; **nie** ujawnia haseł w postaci jawnej.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Pobierz geolokalizację IP, informacje o centrum danych, ASN, proxy/VPN i powiązane pola wzbogacające. Limity zależą od aktualnego planu.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolokalizacja IP i wzbogacanie informacji zorientowane na OSINT, obejmujące wybrane punkty danych. Sprawdź aktualne warunki dotyczące zastosowań komercyjnych.

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
Sprawdź domenę (rejestratora, daty rejestracji i wygaśnięcia, serwery nazw, hostingowy adres IP i kraj) lub adres IP (inne hostowane na nim domeny), a także zweryfikuj, czy domena lub adres IP znajdują się na bezpłatnych listach zasobów naruszonych NetAPI: domen phishingowych i domen malware skierowanych do sinkhole oraz adresów, które zaatakowały czujniki honeypot w ciągu ostatnich 48 godzin. Wyszukiwanie w witrynie i API do sprawdzania zasobów naruszonych nie wymagają konta; dostęp do API wyszukiwania wymaga płatnego planu.


[DNSDumpster](https://dnsdumpster.com/) udostępnia wyniki rozpoznania DNS.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) udostępnia informacje o witrynach, hostingu i infrastrukturze internetowej.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) udostępnia internetowy interfejs do wykrywania subdomen.<sup>[[31]](#references)</sup>

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
- [24] [Badania Cornell — protokoły sprawdzania naruszonych danych uwierzytelniających (w tym GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [Wyszukiwarka subdomen NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [Dokumentacja API NetAPI](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
