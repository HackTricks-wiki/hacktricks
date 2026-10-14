# API do rozpoznania i threat intelligence

{{#include ../../banners/hacktricks-training.md}}

Usługi te wspierają procesy rozpoznania, oceny reputacji, sprawdzania wycieków lub wzbogacania danych. Ich API, limity, ceny i dozwolone zastosowania często się zmieniają; przed przesłaniem identyfikatorów klientów lub wrażliwych danych sprawdź aktualną dokumentację dostawcy oraz autoryzację do przeprowadzenia działań. Sekwencję wykrywania zasobów opisuje [External Recon Methodology](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Sprawdź, czy adres IP był powiązany z podejrzaną lub złośliwą aktywnością. Dostęp może wymagać konta lub klucza API.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Sprawdź, czy adres IP, nazwa użytkownika lub adres e-mail były powiązane z automatyczną rejestracją kont lub inną zgłoszoną aktywnością botów.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Znajdź i zweryfikuj służbowe adresy e-mail oraz wzorce kontaktów powiązane z domeną. Sprawdź aktualny plan, aby poznać limity zapytań i dozwolone zastosowania.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Wyszukuj wskaźniki threat intelligence oraz aktywność powiązaną z adresami IP i domenami.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Wzbogać adres e-mail, domenę lub nazwę firmy o dostępne dane biznesowe/profilowe. Zakres danych, dostęp i ograniczenia dotyczące prywatności zależą od aktualnego produktu i planu.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Ustal technologie wykryte na stronach internetowych i uzyskaj dane historyczne lub informacje o powiązaniach, jeśli wybrany plan na to pozwala.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Sprawdź, czy adres IP jest powiązany z podejrzaną lub złośliwą aktywnością. Zweryfikuj aktualne plany API i limity.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Sprawdź kategoryzację FortiGuard i dane threat intelligence dotyczące domen, adresów URL lub adresów IP. Dostępność zależy od usługi.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Sprawdź, czy adres IP znajduje się na liście adresów zgłoszonych w związku ze spamem.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Pobierz ocenę reputacji domeny na podstawie społeczności usługi i innych sygnałów.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Uzyskaj geolokalizację, ASN, nazwę organizacji i powiązane metadane adresu IP. Sprawdź aktualny plan, aby poznać limity.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Platforma udostępnia dane DNS i informacje o infrastrukturze, takie jak historyczne rozpoznania, domeny powiązane z adresami IP lub serwerami nazw oraz pokrewne rekordy. Historyczne dane DNS mogą ujawnić wcześniejszy adres origin, ale nie pozwalają niezawodnie ominąć CDN i wymagają weryfikacji.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Wzbogać adres e-mail, domenę lub nazwę firmy o dostępne atrybuty dotyczące tożsamości i działalności. Przetwarzaj dane osobowe zgodnie z wymogami autoryzacji i ochrony prywatności.

## RiskIQ / Microsoft Defender Threat Intelligence (przejście ze starszej usługi) <sup>[[14]](#references)</sup>

Możliwości RiskIQ PassiveTotal zostały przeniesione do Microsoft Defender Threat Intelligence. Dostęp do produktu, API i zakres zachowanych funkcji uległy zmianie, dlatego korzystaj z aktualnej dokumentacji Microsoftu, a nie ze starszych założeń dotyczących PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Przeszukuj domeny, adresy IP, adresy e-mail oraz zindeksowane dane historyczne lub leaked, zgodnie z ograniczeniami dostępu usługi.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Wyszukuj adresy IP i inne wskaźniki, aby uzyskać dane threat intelligence i informacje o reputacji.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Wyszukuj adresy IP lub zakresy, aby sprawdzić obserwacje skanowania internetu i typowej aktywności usług. Sprawdź aktualne warunki wersji próbnej i dostępu społecznościowego.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Pobierz informacje o skanach internetu i usługach dla adresu IP, hosta lub zapytania wyszukiwania. Dostęp do API zależy od planu konta.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Przeszukuj zbiory danych dotyczące hostów, certyfikatów, domen i usług internetowych; model danych i zakres Censys różnią się od Shodan.

## [Wyszukiwarka bucketów GrayHatWarfare](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Przeszukuj indeks dostawcy zawierający publicznie zaobserwowane obiekty i buckety w chmurze według słów kluczowych.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Przeszukuj zindeksowane dane z wycieków pod kątem adresów e-mail, nazw użytkowników, domen i powiązanych rekordów. Korzystaj z usługi wyłącznie za zgodą i unikaj niepotrzebnego ujawniania danych z wycieków.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Przeszukuj zindeksowaną treść paste pod kątem wystąpień adresu e-mail lub innego terminu. Przed integracją sprawdź, czy usługa nadal działa.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Pobierz sygnały reputacji i ryzyka dotyczące adresu e-mail.

## GhostProject (historyczna usługa) <sup>[[24]](#references)</sup>

Usługa historycznie reklamowała wyszukiwanie w danych leaked zawierających adresy e-mail i hasła. Traktuj ją jako usługę zewnętrzną wysokiego ryzyka i przed użyciem sprawdź jej dostępność, legalność oraz posiadaną autoryzację.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Uzyskaj dane ze skanów internetu, informacje o ekspozycji i dane threat intelligence dotyczące adresów IP oraz powiązanych zasobów.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Sprawdź, czy adres e-mail lub zweryfikowana domena występują w znanych wyciekach. Osobna usługa Pwned Passwords sprawdza hashe haseł na podstawie prefiksu; **nie** ujawnia haseł w postaci jawnego tekstu.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Pobierz geolokalizację IP, informacje o centrum danych, ASN, proxy/VPN i inne powiązane pola wzbogacające. Limity zależą od aktualnego planu.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolokalizacja IP i wzbogacanie danych zorientowane na OSINT, obejmujące wybrane punkty danych. Sprawdź aktualne warunki dotyczące użytku komercyjnego.


[DNSDumpster](https://dnsdumpster.com/) udostępnia wyniki rozpoznania DNS.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) udostępnia informacje o witrynach, hostingu i infrastrukturze internetowej.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) udostępnia internetowy interfejs do wykrywania subdomen.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [API BotScout](https://botscout.com/api.htm)
- [3] [API Hunter](https://hunter.io/api-documentation)
- [4] [API AlienVault OTX](https://otx.alienvault.com/api)
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
- [24] [Badania Cornell — Protokoły sprawdzania ujawnionych danych uwierzytelniających (w tym GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [API Have I Been Pwned](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [Wyszukiwarka subdomen NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
