# Infrastruktura autoryzowanego red teamu

W przypadku trwałych urządzeń lokalnych użyj projektu [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) oraz runbooka dotyczącego podejrzanego wykrycia.

W profesjonalnym red teamie celem jest **kontrolowana atrybucja**, a nie uniknięcie odpowiedzialności. Cel nie powinien w prosty sposób zobaczyć domowego adresu IP ani osobistych kont operatora, natomiast właściciel engagementu musi móc zidentyfikować źródło, zatrzymać operację, obsłużyć zgłoszenia nadużyć, zachować dowody i wykazać posiadanie autoryzacji.

Ta strona stanowi bazę wdrożeniową dla zgodnego z prawem engagementu. Aby zapoznać się z tradecraftem przeciwnika, który ma być emulowany — w tym z wykorzystaniem przejętych ORB, residential relays, frontingu, dead drops i pobliskich wireless pivots — zacznij od [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) oraz [Government and APT Case Studies](government-and-apt-case-studies.md), a następnie odtwórz wymaganą telemetrię w [autoryzowanych laboratoriach](authorized-adversary-emulation-labs.md).

NIST definiuje rules of engagement (ROE) jako ustanowione wcześniej ograniczenia, które przyznają uprawnienia do określonych działań testowych.<sup>[[1]](#references)</sup> Architektura prywatności nie może rozszerzać tych uprawnień.

## Wybór wzorca egressu

| Wzorzec | Najlepsze zastosowanie | Co widzi cel | Co widzi provider/lokalny obserwator | Odpowiedzialność |
|---|---|---|---|---|
| VPN/jump host zapewniony przez klienta | Większość assessmentów | Zakres adresów klienta | Tożsamość klienta i dostęp operatora | Najsilniejsza |
| Bastion organizacji red teamu | Powtarzalny, kontrolowany egress | Zakres organizacji | Hosting provider i organizację | Silna |
| VPS przeznaczony dla engagementu | Izolowanie klientów/kampanii | Adres VPS | Konto hosta, billing, logi control-plane i dostępu | Silna, jeśli udokumentowana |
| Zatwierdzony komercyjny VPN | Research/scanning dozwolone przez providera i ROE | Współdzielony/dedykowany egress VPN | Konto VPN i połączenie źródłowe | Średnia |
| Tor Browser | Web research wymagający unlinkability względem celu | Węzeł wyjściowy Tor | Sieć lokalna widzi Tor/bridge; cel widzi Tor | Słabe dopasowanie do atrybucji źródła opartej na allowliście |
| Zatwierdzony przez klienta drop lokalny | Symulacja wewnętrzna | Urządzenie/adres lokalny | Sieć lokalna i dostawca zdalnego tunelu | Silna, jeśli zinwentaryzowana |
| Zgodne z prawem guest Wi-Fi | Niskiego ryzyka zastosowania administracyjne/researchowe | Publiczny adres IP obiektu lub egress tunelu | Obiekt, ISP, VPN/Tor | Słaba i fizycznie obserwowalna |

W przypadku większości prac egress zapewniony przez klienta lub kontrolowany przez organizację, ze stałym adresem, jest bezpieczniejszy i szybszy niż konsumenckie usługi anonimowości. Umożliwia także obrońcom dodanie do allowlisty, monitorowanie lub celowe **nie**dodawanie do allowlisty znanych zakresów źródłowych, zgodnie z projektem ćwiczenia.

## Aneks infrastruktury ROE

Przed wdrożeniem zapisz:

- podmioty prawne udzielające i otrzymujące autoryzację;
- dokładne cele i wyraźne wykluczenia;
- czasy rozpoczęcia/zakończenia, strefę czasową i dozwolone techniki;
- adresy IP źródłowe, nazwy autonomous system/providerów, domeny, redirectory, infrastrukturę pocztową i identyfikatory urządzeń lokalnych;
- czy dozwolone są phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence lub usługi stron trzecich;
- zatwierdzenia klienta i providera, w tym ewentualny numer wcześniejszego powiadomienia;
- frazę awaryjnego zatrzymania, całodobowe kontakty klienta i providera ds. abuse oraz maksymalny czas reakcji;
- klasy danych, które mogą zostać zebrane, szyfrowanie, dostęp, retencję i usuwanie;
- wymagania dotyczące dowodów i logowania, w tym informację, kto przechowuje mapowanie publicznej infrastruktury na operatora;
- teardown, wygaśnięcie domeny, unieważnienie certyfikatów, rotację credentials, odzyskanie urządzeń i końcowe poświadczenie.

Zweryfikuj, czy publiczne adresy IP i domeny są faktycznie kontrolowane przez stronę udzielającą autoryzacji lub wyraźnie uwzględnione w zakresie. NIST SP 800-115 zaleca potwierdzenie, że publiczne adresy celów znajdują się pod nadzorem organizacji przed rozpoczęciem testów.<sup>[[2]](#references)</sup>

## Szybki egress dla konkretnego engagementu

### Workflow budowy

1. **Utwórz konto/projekt engagementu** w organizacji red teamu, używając prawidłowych danych billingowych i danych właściciela. Oddziel role, klucze API, budżety i audit logs od pozostałych klientów.
2. **Sprawdź zasady każdego providera.** Providerzy cloud, VPS, CDN, domen, poczty i VPN mają różne reguły. AWS na przykład zezwala na określone assessmenty, ale wymaga wcześniejszego zatwierdzenia dla hosted C2/covert simulations i zabrania wymienionych działań.<sup>[[3]](#references)</sup>
3. **Przydziel stałe adresy egressu** i umieść je w aneksie ROE. Unikaj szybkiej rotacji IP/zasobów; komplikuje ona incident response i może naruszać zasady providera.
4. **Zabezpiecz zarządzanie:** SSH wyłącznie z użyciem kluczy lub identity-aware management plane, phishing-resistant MFA, oddzielna sieć administracyjna, least privilege, zaktualizowane obrazy, brak publicznych portów administracyjnych i szyfrowane przechowywanie sekretów.
5. **Utwórz ścieżkę full-tunnel** z endpointu operatora do bastionu. Świadomie kieruj DNS i IPv6 oraz wymuś blokadę firewalla, gdy tunel jest wyłączony.
6. **Ogranicz wychodzące destinations i porty** do autoryzowanego zakresu, jeśli jest to możliwe. Ograniczaj rate scannerów i umieść nieodwracalne/destrukcyjne techniki za oddzielnym approval gate.
7. **Loguj na potrzeby odpowiedzialności, nie nadzoru:** uwierzytelnianie operatora, zmiany konfiguracji, rozpoczęcie/zatrzymanie, adres źródłowy, destination w zakresie oraz identyfikatory narzędzi/jobów. Unikaj przechwytywania payloadów/credentials, chyba że wymaga tego ćwiczenie i zapewnia to plan danych.
8. **Zweryfikuj działanie przez kontrolowany endpoint** należący do organizacji: obserwowane IPv4/IPv6, ścieżkę DNS, reverse DNS, zegar, zachowanie source portu, awarie/ponowne połączenia oraz kontakt abuse providera.
9. **Udostępnij mapę atrybucji bezpiecznie** kontrolerowi ćwiczenia lub uzgodnionemu kontaktowi escrow. Nie publikuj jej zespołowi celu, jeśli blind detection jest częścią testu.

### Architektura
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
VPS jest pseudonimowy wyłącznie dla miejsca docelowego. Host może posiadać dane kontaktowe, rozliczeniowe, dotyczące tożsamości, źródłowego adresu IP, API, urządzenia, lokalizacji i użycia; sama widoczna dla klienta historia AWS CloudTrail może ujawnić aktywność zarządczą.<sup>[[4]](#references)</sup> Płacenie za hosting kryptowalutą nie usuwa tych danych.

## Domeny i certyfikaty

- Używaj konta registrar przeznaczonego dla danego engagementu i należącego do organizacji.
- Włącz registrar lock, DNSSEC tam, gdzie jest obsługiwany, MFA/security keys oraz auto-renew wyłącznie na zatwierdzony okres.
- Używaj registration privacy w celu ograniczenia publicznego ujawnienia danych, a nie do fałszywego przedstawiania informacji o rejestrującym. Polityka ICANN wymaga od registrarów gromadzenia danych rejestracyjnych, nawet gdy ich publiczne wyświetlanie jest ukryte lub realizowane przez proxy.<sup>[[5]](#references)</sup>
- Unikaj nazw, które bezprawnie podszywają się pod niepowiązane strony. Domeny typosquatting/lookalike wymagają wyraźnej zgody klienta i providera.
- Zinwentaryzuj DNS, certyfikaty, konfigurację CDN/redirectora oraz third-party analytics, które mogłyby ujawnić operatorów lub klientów.
- Podczas teardown usuń rekordy, unieważnij certyfikaty/tokeny, zachowaj uzgodnione dowody i zdecyduj, czy domena powinna zostać zachowana defensywnie.

## Autoryzowane on-site drop nodes

Raspberry Pi lub podobne urządzenie jest dopuszczalne wyłącznie wtedy, gdy właściciel obiektu/sieci oraz klient wyraźnie autoryzują jego dokładne umiejscowienie i działanie. Bezpieczny plan:

1. Zapisz numer seryjny urządzenia, MAC/private-MAC policy, zdjęcie, właściciela, dokładną zatwierdzoną lokalizację, źródło zasilania, termin odbioru oraz kontakt w sprawie naruszenia.
2. Użyj minimalnego, podpisanego obrazu, zaszyfrowanych sekretów, storage tylko do odczytu lub możliwego do odzyskania, host firewall, automatic security updates tam, gdzie jest to praktyczne, oraz bez default credentials.
3. Skonfiguruj komunikację wyłącznie wychodzącą do nazwanego endpointu engagementu. Nie udostępniaj nieuwierzytelnionego listenera.
4. Ogranicz dozwolone destinations i capabilities. Packet capture, credential collection, wireless impersonation oraz lateral movement muszą być każdorazowo wyraźnie autoryzowane.
5. Używaj mutual authentication, short-lived keys, remote kill, health reporting oraz limitów bandwidth.
6. Upewnij się, że utrata lub kradzież nie ujawni ponownie używalnych credentials ani danych klienta.
7. Umieść retrieval oraz secure wipe/decommission w kalendarzu; uzyskaj podpisany recovery record.

Nie ukrywaj sprzętu w kawiarni, hotelu, współdzielonym biurze, na posesji sąsiada ani w miejscu publicznym bez pisemnej zgody właściciela/operatora.

## Guest networks i travel routers

Jeśli autoryzowany scenariusz wymaga dostępu gościnnego:

- zweryfikuj SSID i acceptable-use policy z obiektem/klientem;
- użyj należącego do organizacji travel routera lub low-trust bridge device, aby odizolować uprzywilejowaną stację roboczą;
- obsłuż captive portals poza uprzywilejowaną stacją roboczą;
- uruchom zatwierdzony tunnel przed ruchem assessmentu;
- potwierdź, że tethered devices faktycznie korzystają z tego tunelu;
- załóż, że obiekt może korelować radio association, portal, fizyczną obecność oraz dane z kamer i płatności;
- nigdy nie omijaj access control, nie klonuj innego urządzenia, nie atakuj Wi-Fi ani nie zostawiaj sprzętu.

## Separacja operacyjna

- Jeden klient/engagement na endpoint compartment, cloud project, secrets set, domain group, redirector set oraz evidence store.
- Nie używaj prywatnego e-maila, browser sync, numeru telefonu, cloud drive, klucza SSH/GPG, code-signing identity ani payment reimbursement poza zatwierdzonymi systemami organizacji.
- Nie używaj ponownie charakterystycznej konfiguracji payloadu, callback paths, certyfikatów ani publicznych repozytoriów między klientami, chyba że projekt ćwiczenia akceptuje fingerprinting.
- Nadaj infrastrukturze kill date i budget alert. Osierocone systemy stają się zagrożeniem zarówno dla klienta, jak i Internetu.
- Zachowaj wystarczającą wewnętrzną możliwość przypisania działań, aby badać wypadki. „Brak logów” jest zwykle niezgodny z profesjonalnymi obowiązkami dotyczącymi dowodów i bezpieczeństwa.

## Niewidoczne dla obrońców, możliwe do przypisania kontrolerowi

Gdy celem ćwiczenia jest pomiar detekcji, a nie testowanie allowlisty, docelowy SOC może pozostać nieświadomy bez pozbawiania operacji rozliczalności:

1. Kontroler ćwiczenia zatwierdza każde publiczne źródło, domenę, certyfikat i on-site device, ale nie przekazuje tej listy SOC.
2. Kontroler przechowuje mapowanie źródło–engagement/operator w oddzielnym zaszyfrowanym vault z awaryjnym dostępem wymagającym dwóch osób.
3. Każde zadanie operatora otrzymuje podpisany manifest zawierający scope, time window, source compartment oraz nieodwracalny job identifier. Cel nie musi widzieć manifestu podczas normalnego działania.
4. Zdarzenia audytowe bastiona są łańcuchowane lub wysyłane w trybie append-only do storage kontrolera, aby operator nie mógł po cichu zmienić przypisania po incydencie.
5. Całodobowy provider-abuse contact posiada verification phrase/reference potwierdzające autoryzację bez publicznego ujawniania klienta.
6. Każda ścieżka implementuje out-of-band stop channel, który nie zależy od assessment C2, sieci celu ani konta jednego operatora.
7. Przed rozpoczęciem live testing wyślij benign canaries z każdego źródła. Potwierdź, że kontroler może je zidentyfikować i zatrzymać w czasie określonym przez ROE.
8. Po ćwiczeniu porównaj telemetry SOC z ledgerem kontrolera, ujawnij listę źródeł oraz wyjaśnij pominięte/błędne detekcje.

Nie dodawaj anti-forensics, niszczenia logów, skompromitowanych relayów ani fałszywych tożsamości subscriberów. Podważają one rozliczalne testowanie, zamiast je ulepszać.

## Lista kontrolna teardown

- [ ] Kontroler ćwiczenia potwierdza zatrzymanie.
- [ ] C2, tunnelle, redirectory, poczta, VPN i zaplanowane zadania są wyłączone.
- [ ] On-site devices są fizycznie odzyskane i rozliczone.
- [ ] Tokeny, API keys, klucze SSH, certyfikaty i przechwycone credentials są unieważnione/wymienione.
- [ ] DNS i zasoby cloud są usunięte lub przekazane do defensywnego zachowania.
- [ ] Dane klienta są zwrócone, zachowane lub zniszczone zgodnie z umową.
- [ ] Wymagane dane finansowe, audytowe i autoryzacyjne pozostają zaszyfrowane i objęte kontrolą dostępu.
- [ ] Sprawy dotyczące abuse u providera są zamknięte, a klient otrzymuje końcowe source indicators.
- [ ] Drugi operator weryfikuje, że żadna infrastruktura nie pozostaje aktywna.

## References

- [1] [NIST CSRC — Zasady zaangażowania](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Przewodnik techniczny po testowaniu i ocenie bezpieczeństwa informacji](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Zasady obsługi klienta dotyczące pentesting](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Informacja o prywatności](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Polityka danych rejestracyjnych](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
